// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"
#include "checksum.h"
#include "errcode.h"
#include "error.h"
#include "super.h"
#include "super-io.h"

#include <linux/crc32c.h>
#include <linux/xxhash.h>
#include <linux/key.h>
#include <linux/random.h>
#include <linux/ratelimit.h>
#include <crypto/chacha.h>
#include <crypto/poly1305.h>
#include <keys/user-type.h>

/*
 * bch2_checksum state is an abstraction of the checksum state calculated over different pages.
 * it features page merging without having the checksum algorithm lose its state.
 * for native checksum aglorithms (like crc), a default seed value will do.
 * for hash-like algorithms, a state needs to be stored
 */

struct bch2_checksum_state {
	union {
		u64 seed;
		struct xxh64_state h64state;
	};
	unsigned int type;
};

static void bch2_checksum_init(struct bch2_checksum_state *state)
{
	switch (state->type) {
	case BCH_CSUM_none:
	case BCH_CSUM_crc32c:
	case BCH_CSUM_crc64:
		state->seed = 0;
		break;
	case BCH_CSUM_crc32c_nonzero:
		state->seed = U32_MAX;
		break;
	case BCH_CSUM_crc64_nonzero:
		state->seed = U64_MAX;
		break;
	case BCH_CSUM_xxhash:
		xxh64_reset(&state->h64state, 0);
		break;
	default:
		BUG();
	}
}

static u64 bch2_checksum_final(const struct bch2_checksum_state *state)
{
	switch (state->type) {
	case BCH_CSUM_none:
	case BCH_CSUM_crc32c:
	case BCH_CSUM_crc64:
		return state->seed;
	case BCH_CSUM_crc32c_nonzero:
		return state->seed ^ U32_MAX;
	case BCH_CSUM_crc64_nonzero:
		return state->seed ^ U64_MAX;
	case BCH_CSUM_xxhash:
		return xxh64_digest(&state->h64state);
	default:
		BUG();
	}
}

static void bch2_checksum_update(struct bch2_checksum_state *state, const void *data, size_t len)
{
	switch (state->type) {
	case BCH_CSUM_none:
		return;
	case BCH_CSUM_crc32c_nonzero:
	case BCH_CSUM_crc32c:
		state->seed = crc32c(state->seed, data, len);
		break;
	case BCH_CSUM_crc64_nonzero:
	case BCH_CSUM_crc64:
		state->seed = crc64_be(state->seed, data, len);
		break;
	case BCH_CSUM_xxhash:
		xxh64_update(&state->h64state, data, len);
		break;
	default:
		BUG();
	}
}

static void bch2_chacha20_init(struct chacha_state *state,
			       const struct bch_key *key, struct nonce nonce)
{
	u32 key_words[CHACHA_KEY_SIZE / sizeof(u32)];

	BUILD_BUG_ON(sizeof(key_words) != sizeof(*key));
	memcpy(key_words, key, sizeof(key_words));
	le32_to_cpu_array(key_words, ARRAY_SIZE(key_words));

	BUILD_BUG_ON(sizeof(nonce) != CHACHA_IV_SIZE);
	chacha_init(state, key_words, (const u8 *)nonce.d);

	memzero_explicit(key_words, sizeof(key_words));
}

void bch2_chacha20(const struct bch_key *key, struct nonce nonce,
		   void *data, size_t len)
{
	struct chacha_state state;

	bch2_chacha20_init(&state, key, nonce);
	chacha20_crypt(&state, data, data, len);
	chacha_zeroize_state(&state);
}

static void bch2_poly1305_init(struct poly1305_desc_ctx *desc,
			       struct bch_fs *c, struct nonce nonce)
{
	u8 key[POLY1305_KEY_SIZE] = { 0 };

	nonce.d[3] ^= BCH_NONCE_POLY;

	bch2_chacha20(&c->chacha20_key, nonce, key, sizeof(key));
	poly1305_init(desc, key);
}

struct bch_csum bch2_checksum(struct bch_fs *c, unsigned type,
			      struct nonce nonce, const void *data, size_t len)
{
	switch (type) {
	case BCH_CSUM_none:
	case BCH_CSUM_crc32c_nonzero:
	case BCH_CSUM_crc64_nonzero:
	case BCH_CSUM_crc32c:
	case BCH_CSUM_xxhash:
	case BCH_CSUM_crc64: {
		struct bch2_checksum_state state;

		state.type = type;

		bch2_checksum_init(&state);
		bch2_checksum_update(&state, data, len);

		return (struct bch_csum) { .lo = cpu_to_le64(bch2_checksum_final(&state)) };
	}

	case BCH_CSUM_chacha20_poly1305_80:
	case BCH_CSUM_chacha20_poly1305_128: {
		struct poly1305_desc_ctx dctx;
		u8 digest[POLY1305_DIGEST_SIZE];
		struct bch_csum ret = { 0 };

		bch2_poly1305_init(&dctx, c, nonce);
		poly1305_update(&dctx, data, len);
		poly1305_final(&dctx, digest);

		memcpy(&ret, digest, bch_crc_bytes[type]);
		return ret;
	}
	default:
		return (struct bch_csum) {};
	}
}

int bch2_encrypt(struct bch_fs *c, unsigned type,
		  struct nonce nonce, void *data, size_t len)
{
	if (!bch2_csum_type_is_encryption(type))
		return 0;

	if (bch2_fs_inconsistent_on(!c->chacha20_key_set,
				    c, "attempting to encrypt without encryption key"))
		return bch_err_throw(c, no_encryption_key);

	bch2_chacha20(&c->chacha20_key, nonce, data, len);
	return 0;
}

static struct bch_csum __bch2_checksum_bio(struct bch_fs *c, unsigned type,
					   struct nonce nonce, struct bio *bio,
					   struct bvec_iter *iter)
{
	struct bio_vec bv;

	switch (type) {
	case BCH_CSUM_none:
		return (struct bch_csum) { 0 };
	case BCH_CSUM_crc32c_nonzero:
	case BCH_CSUM_crc64_nonzero:
	case BCH_CSUM_crc32c:
	case BCH_CSUM_xxhash:
	case BCH_CSUM_crc64: {
		struct bch2_checksum_state state;

		state.type = type;
		bch2_checksum_init(&state);

#ifdef CONFIG_HIGHMEM
		__bio_for_each_segment(bv, bio, *iter, *iter) {
			void *p = kmap_local_page(bv.bv_page) + bv.bv_offset;

			bch2_checksum_update(&state, p, bv.bv_len);
			kunmap_local(p);
		}
#else
		__bio_for_each_bvec(bv, bio, *iter, *iter)
			bch2_checksum_update(&state, page_address(bv.bv_page) + bv.bv_offset,
				bv.bv_len);
#endif
		return (struct bch_csum) { .lo = cpu_to_le64(bch2_checksum_final(&state)) };
	}

	case BCH_CSUM_chacha20_poly1305_80:
	case BCH_CSUM_chacha20_poly1305_128: {
		struct poly1305_desc_ctx dctx;
		u8 digest[POLY1305_DIGEST_SIZE];
		struct bch_csum ret = { 0 };

		bch2_poly1305_init(&dctx, c, nonce);

#ifdef CONFIG_HIGHMEM
		__bio_for_each_segment(bv, bio, *iter, *iter) {
			void *p = kmap_local_page(bv.bv_page) + bv.bv_offset;

			poly1305_update(&dctx, p, bv.bv_len);
			kunmap_local(p);
		}
#else
		__bio_for_each_bvec(bv, bio, *iter, *iter)
			poly1305_update(&dctx,
				page_address(bv.bv_page) + bv.bv_offset,
				bv.bv_len);
#endif
		poly1305_final(&dctx, digest);

		memcpy(&ret, digest, bch_crc_bytes[type]);
		return ret;
	}
	default:
		return (struct bch_csum) {};
	}
}

struct bch_csum bch2_checksum_bio(struct bch_fs *c, unsigned type,
				  struct nonce nonce, struct bio *bio)
{
	struct bvec_iter iter = bio->bi_iter;

	return __bch2_checksum_bio(c, type, nonce, bio, &iter);
}

int __bch2_encrypt_bio(struct bch_fs *c, unsigned type,
		     struct nonce nonce, struct bio *bio)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	struct chacha_state chacha_state;
	int ret = 0;

	if (bch2_fs_inconsistent_on(!c->chacha20_key_set,
				    c, "attempting to encrypt without encryption key"))
		return bch_err_throw(c, no_encryption_key);

	bch2_chacha20_init(&chacha_state, &c->chacha20_key, nonce);

	bio_for_each_segment(bv, bio, iter) {
		void *p;

		/*
		 * chacha_crypt() assumes that the length is a multiple of
		 * CHACHA_BLOCK_SIZE on any non-final call.
		 */
		if (!IS_ALIGNED(bv.bv_len, CHACHA_BLOCK_SIZE)) {
			bch_err_ratelimited(c, "bio not aligned for encryption");
			ret = -EIO;
			break;
		}

		p = bvec_kmap_local(&bv);
		chacha20_crypt(&chacha_state, p, p, bv.bv_len);
		kunmap_local(p);
	}
	chacha_zeroize_state(&chacha_state);
	return ret;
}

struct bch_csum bch2_checksum_merge(unsigned type, struct bch_csum a,
				    struct bch_csum b, size_t b_len)
{
	struct bch2_checksum_state state;

	state.type = type;
	bch2_checksum_init(&state);
	state.seed = le64_to_cpu(a.lo);

	BUG_ON(!bch2_checksum_mergeable(type));

	while (b_len) {
		unsigned page_len = min_t(unsigned, b_len, PAGE_SIZE);

		bch2_checksum_update(&state,
				page_address(ZERO_PAGE(0)), page_len);
		b_len -= page_len;
	}
	a.lo = cpu_to_le64(bch2_checksum_final(&state));
	a.lo ^= b.lo;
	a.hi ^= b.hi;
	return a;
}

int bch2_rechecksum_bio(struct bch_fs *c, struct bio *bio,
			struct bversion version,
			struct bch_extent_crc_unpacked crc_old,
			struct bch_extent_crc_unpacked *crc_a,
			struct bch_extent_crc_unpacked *crc_b,
			unsigned len_a, unsigned len_b,
			unsigned new_csum_type)
{
	struct bvec_iter iter = bio->bi_iter;
	struct nonce nonce = extent_nonce(version, crc_old);
	struct bch_csum merged = { 0 };
	struct crc_split {
		struct bch_extent_crc_unpacked	*crc;
		unsigned			len;
		unsigned			csum_type;
		struct bch_csum			csum;
	} splits[3] = {
		{ crc_a, len_a, new_csum_type, { 0 }},
		{ crc_b, len_b, new_csum_type, { 0 } },
		{ NULL,	 bio_sectors(bio) - len_a - len_b, new_csum_type, { 0 } },
	}, *i;
	bool mergeable = crc_old.csum_type == new_csum_type &&
		bch2_checksum_mergeable(new_csum_type);
	unsigned crc_nonce = crc_old.nonce;

	BUG_ON(len_a + len_b > bio_sectors(bio));
	BUG_ON(crc_old.uncompressed_size != bio_sectors(bio));
	BUG_ON(crc_is_compressed(crc_old));
	BUG_ON(bch2_csum_type_is_encryption(crc_old.csum_type) !=
	       bch2_csum_type_is_encryption(new_csum_type));

	for (i = splits; i < splits + ARRAY_SIZE(splits); i++) {
		iter.bi_size = i->len << 9;
		if (mergeable || i->crc)
			i->csum = __bch2_checksum_bio(c, i->csum_type,
						      nonce, bio, &iter);
		else
			bio_advance_iter(bio, &iter, i->len << 9);
		nonce = nonce_add(nonce, i->len << 9);
	}

	if (mergeable)
		for (i = splits; i < splits + ARRAY_SIZE(splits); i++)
			merged = bch2_checksum_merge(new_csum_type, merged,
						     i->csum, i->len << 9);
	else
		merged = bch2_checksum_bio(c, crc_old.csum_type,
				extent_nonce(version, crc_old), bio);

	if (bch2_crc_cmp(merged, crc_old.csum) && !c->opts.no_data_io) {
		CLASS(printbuf, buf)();
		prt_printf(&buf, "checksum error in %s() (memory corruption or bug?)\n"
			   "  expected %0llx:%0llx got %0llx:%0llx (old type ",
			   __func__,
			   crc_old.csum.hi,
			   crc_old.csum.lo,
			   merged.hi,
			   merged.lo);
		bch2_prt_csum_type(&buf, crc_old.csum_type);
		prt_str(&buf, " new type ");
		bch2_prt_csum_type(&buf, new_csum_type);
		prt_str(&buf, ")");
		WARN_RATELIMIT(1, "%s", buf.buf);
		return bch_err_throw(c, recompute_checksum);
	}

	for (i = splits; i < splits + ARRAY_SIZE(splits); i++) {
		if (i->crc)
			*i->crc = (struct bch_extent_crc_unpacked) {
				.csum_type		= i->csum_type,
				.compression_type	= crc_old.compression_type,
				.compressed_size	= i->len,
				.uncompressed_size	= i->len,
				.offset			= 0,
				.live_size		= i->len,
				.nonce			= crc_nonce,
				.csum			= i->csum,
			};

		if (bch2_csum_type_is_encryption(new_csum_type))
			crc_nonce += i->len;
	}

	return 0;
}

/* BCH_SB_FIELD_crypt: */

static int bch2_sb_crypt_validate(struct bch_sb *sb, struct bch_sb_field *f,
				  enum bch_validate_flags flags, struct printbuf *err)
{
	struct bch_sb_field_crypt *crypt = field_to_type(f, crypt);

	if (vstruct_bytes(&crypt->field) < sizeof(*crypt)) {
		prt_printf(err, "wrong size (got %zu should be %zu)",
		       vstruct_bytes(&crypt->field), sizeof(*crypt));
		return -BCH_ERR_invalid_sb_crypt;
	}

	if (BCH_CRYPT_KDF_TYPE(crypt)) {
		prt_printf(err, "bad kdf type %llu", BCH_CRYPT_KDF_TYPE(crypt));
		return -BCH_ERR_invalid_sb_crypt;
	}

	return 0;
}

static void bch2_sb_crypt_to_text(struct printbuf *out, struct bch_sb *sb,
				  struct bch_sb_field *f)
{
	struct bch_sb_field_crypt *crypt = field_to_type(f, crypt);

	prt_printf(out, "KFD:               %llu\n", BCH_CRYPT_KDF_TYPE(crypt));
	prt_printf(out, "scrypt n:          %llu\n", BCH_KDF_SCRYPT_N(crypt));
	prt_printf(out, "scrypt r:          %llu\n", BCH_KDF_SCRYPT_R(crypt));
	prt_printf(out, "scrypt p:          %llu\n", BCH_KDF_SCRYPT_P(crypt));
}

const struct bch_sb_field_ops bch_sb_field_ops_crypt = {
	.validate	= bch2_sb_crypt_validate,
	.to_text	= bch2_sb_crypt_to_text,
};

#ifdef __KERNEL__
static int __bch2_request_key(char *key_description, struct bch_key *key)
{
	int ret;

	struct key *keyring_key = request_key(&key_type_user, key_description, NULL);
	if (IS_ERR(keyring_key))
		return PTR_ERR(keyring_key);

	scoped_guard(rwsem_read, &keyring_key->sem) {
		const struct user_key_payload *ukp = dereference_key_locked(keyring_key);
		if (ukp->datalen == sizeof(*key)) {
			memcpy(key, ukp->data, ukp->datalen);
			ret = 0;
		} else {
			ret = -EINVAL;
		}
	}
	key_put(keyring_key);

	return ret;
}
#else
#include <keyutils.h>

static int __bch2_request_key(char *key_description, struct bch_key *key)
{
	key_serial_t key_id;

	key_id = request_key("user", key_description, NULL,
			     KEY_SPEC_SESSION_KEYRING);
	if (key_id >= 0)
		goto got_key;

	key_id = request_key("user", key_description, NULL,
			     KEY_SPEC_USER_KEYRING);
	if (key_id >= 0)
		goto got_key;

	key_id = request_key("user", key_description, NULL,
			     KEY_SPEC_USER_SESSION_KEYRING);
	if (key_id >= 0)
		goto got_key;

	return -errno;
got_key:

	if (keyctl_read(key_id, (void *) key, sizeof(*key)) != sizeof(*key))
		return -1;

	return 0;
}

#include "crypto.h"
#endif

int bch2_request_key(struct bch_sb *sb, struct bch_key *key)
{
	CLASS(printbuf, key_description)();
	int ret;

	prt_printf(&key_description, "bcachefs:");
	pr_uuid(&key_description, sb->user_uuid.b);

	ret = __bch2_request_key(key_description.buf, key);

#ifndef __KERNEL__
	if (ret) {
		char *passphrase = read_passphrase("Enter passphrase: ");
		struct bch_encrypted_key sb_key;

		bch2_passphrase_check(sb, passphrase,
				      key, &sb_key);
		ret = 0;
	}
#endif

	/* stash with memfd, pass memfd fd to mount */

	return ret;
}

#ifndef __KERNEL__
int bch2_revoke_key(struct bch_sb *sb)
{
	key_serial_t key_id;
	CLASS(printbuf, key_description)();

	prt_printf(&key_description, "bcachefs:");
	pr_uuid(&key_description, sb->user_uuid.b);

	key_id = request_key("user", key_description.buf, NULL, KEY_SPEC_USER_KEYRING);
	if (key_id < 0)
		return errno;

	keyctl_revoke(key_id);

	return 0;
}
#endif

int bch2_decrypt_sb_key(struct bch_fs *c,
			struct bch_sb_field_crypt *crypt,
			struct bch_key *key)
{
	struct bch_encrypted_key sb_key = crypt->key;
	struct bch_key user_key;
	int ret = 0;

	/* is key encrypted? */
	if (!bch2_key_is_encrypted(&sb_key))
		goto out;

	ret = bch2_request_key(c->disk_sb.sb, &user_key);
	if (ret) {
		bch_err(c, "error requesting encryption key: %s", bch2_err_str(ret));
		goto err;
	}

	/* decrypt real key: */
	bch2_chacha20(&user_key, bch2_sb_key_nonce(c), &sb_key, sizeof(sb_key));

	if (bch2_key_is_encrypted(&sb_key)) {
		bch_err(c, "incorrect encryption key");
		ret = -EINVAL;
		goto err;
	}
out:
	*key = sb_key.key;
err:
	memzero_explicit(&sb_key, sizeof(sb_key));
	memzero_explicit(&user_key, sizeof(user_key));
	return ret;
}

#if 0

/*
 * This seems to be duplicating code in cmd_remove_passphrase() in
 * bcachefs-tools, but we might want to switch userspace to use this - and
 * perhaps add an ioctl for calling this at runtime, so we can take the
 * passphrase off of a mounted filesystem (which has come up).
 */
int bch2_disable_encryption(struct bch_fs *c)
{
	guard(mutex)(&c->sb_lock);

	struct bch_sb_field_crypt *crypt = bch2_sb_field_get(c->disk_sb.sb, crypt);
	if (!crypt)
		return -EINVAL;

	/* is key encrypted? */
	ret = 0;
	if (bch2_key_is_encrypted(&crypt->key))
		return 0;

	struct bch_key key;
	int ret = bch2_decrypt_sb_key(c, crypt, &key);
	if (ret)
		return ret;

	crypt->key.magic	= cpu_to_le64(BCH_KEY_MAGIC);
	crypt->key.key		= key;

	SET_BCH_SB_ENCRYPTION_TYPE(c->disk_sb.sb, 0);
	bch2_write_super(c);
	return 0;
}

/*
 * For enabling encryption on an existing filesystem: not hooked up yet, but it
 * should be
 */
int bch2_enable_encryption(struct bch_fs *c, bool keyed)
{
	struct bch_encrypted_key key;
	struct bch_key user_key;
	struct bch_sb_field_crypt *crypt;
	int ret = -EINVAL;

	guard(mutex)(&c->sb_lock);

	/* Do we already have an encryption key? */
	if (bch2_sb_field_get(c->disk_sb.sb, crypt))
		goto err;

	ret = bch2_alloc_ciphers(c);
	if (ret)
		goto err;

	key.magic = cpu_to_le64(BCH_KEY_MAGIC);
	get_random_bytes(&key.key, sizeof(key.key));

	if (keyed) {
		ret = bch2_request_key(c->disk_sb.sb, &user_key);
		if (ret) {
			bch_err(c, "error requesting encryption key: %s", bch2_err_str(ret));
			goto err;
		}

		ret = bch2_chacha_encrypt_key(&user_key, bch2_sb_key_nonce(c),
					      &key, sizeof(key));
		if (ret)
			goto err;
	}

	ret = crypto_skcipher_setkey(&c->chacha20->base,
			(void *) &key.key, sizeof(key.key));
	if (ret)
		goto err;

	crypt = bch2_sb_field_resize(&c->disk_sb, crypt,
				     sizeof(*crypt) / sizeof(u64));
	if (!crypt) {
		ret = bch_err_throw(c, ENOSPC_sb_crypt);
		goto err;
	}

	crypt->key = key;

	/* write superblock */
	SET_BCH_SB_ENCRYPTION_TYPE(c->disk_sb.sb, 1);
	bch2_write_super(c);
err:
	memzero_explicit(&user_key, sizeof(user_key));
	memzero_explicit(&key, sizeof(key));
	return ret;
}
#endif

void bch2_fs_encryption_exit(struct bch_fs *c)
{
	memzero_explicit(&c->chacha20_key, sizeof(c->chacha20_key));
}

int bch2_fs_encryption_init(struct bch_fs *c)
{
	struct bch_sb_field_crypt *crypt;
	int ret;

	crypt = bch2_sb_field_get(c->disk_sb.sb, crypt);
	if (!crypt)
		return 0;

	ret = bch2_decrypt_sb_key(c, crypt, &c->chacha20_key);
	if (ret)
		return ret;
	c->chacha20_key_set = true;
	return 0;
}
