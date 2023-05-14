// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "bkey.h"
#include "bkey_cmp.h"
#include "bkey_methods.h"
#include "bset.h"
#include "util.h"

#include <asm/unaligned.h>

#undef EBUG_ON

#ifdef DEBUG_BKEYS
#define EBUG_ON(cond)		BUG_ON(cond)
#else
#define EBUG_ON(cond)
#endif

const struct bkey_format bch2_bkey_format_current = BKEY_FORMAT_CURRENT;

struct bkey_format_processed bch2_bkey_format_postprocess(const struct bkey_format f)
{
	struct bkey_format_processed ret = { .f = f, .aligned = true };
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	unsigned bit_offset = f.key_u64s * 64;
#else
	unsigned bit_offset = KEY_PACKED_BITS_START;
#endif

	for (unsigned i = 0; i < BKEY_NR_FIELDS; i++) {
		unsigned bits = f.bits_per_field[i];

		if (bits & 7) {
			ret.aligned = false;
			break;
		}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		bit_offset -= bits;
#endif
		ret.offset[i]	= bit_offset / 8;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		bit_offset += bits;
#endif
		ret.mask[i]	= bits ? ~0ULL >> (64 - bits) : 0;
	}

	return ret;
}

void bch2_bkey_packed_to_binary_text(struct printbuf *out,
				     const struct bkey_format *f,
				     const struct bkey_packed *k)
{
	const u64 *p = high_word(f, k);
	unsigned word_bits = 64 - high_bit_offset;
	unsigned nr_key_bits = bkey_format_key_bits(f) + high_bit_offset;
	u64 v = *p & (~0ULL >> high_bit_offset);

	if (!nr_key_bits) {
		prt_str(out, "(empty)");
		return;
	}

	while (1) {
		unsigned next_key_bits = nr_key_bits;

		if (nr_key_bits < 64) {
			v >>= 64 - nr_key_bits;
			next_key_bits = 0;
		} else {
			next_key_bits -= 64;
		}

		bch2_prt_u64_binary(out, v, min(word_bits, nr_key_bits));

		if (!next_key_bits)
			break;

		prt_char(out, ' ');

		p = next_word(p);
		v = *p;
		word_bits = 64;
		nr_key_bits = next_key_bits;
	}
}

#ifdef CONFIG_BCACHEFS_DEBUG

static void bch2_bkey_pack_verify(const struct bkey_packed *packed,
				  const struct bkey *unpacked,
				  const struct bkey_format_processed *format)
{
	struct bkey tmp;

	BUG_ON(bkeyp_val_u64s(format, packed) !=
	       bkey_val_u64s(unpacked));

	BUG_ON(packed->u64s < bkeyp_key_u64s(format, packed));

	tmp = __bch2_bkey_unpack_key(format, packed);

	if (memcmp(&tmp, unpacked, sizeof(struct bkey))) {
		struct printbuf buf = PRINTBUF;

		prt_printf(&buf, "keys differ: format u64s %u fields %u %u %u %u %u\n",
		      format->f.key_u64s,
		      format->f.bits_per_field[0],
		      format->f.bits_per_field[1],
		      format->f.bits_per_field[2],
		      format->f.bits_per_field[3],
		      format->f.bits_per_field[4]);

		prt_printf(&buf, "compiled unpack: ");
		bch2_bkey_to_text(&buf, unpacked);
		prt_newline(&buf);

		prt_printf(&buf, "c unpack:        ");
		bch2_bkey_to_text(&buf, &tmp);
		prt_newline(&buf);

		prt_printf(&buf, "compiled unpack: ");
		bch2_bkey_packed_to_binary_text(&buf, &bch2_bkey_format_current,
						(struct bkey_packed *) unpacked);
		prt_newline(&buf);

		prt_printf(&buf, "c unpack:        ");
		bch2_bkey_packed_to_binary_text(&buf, &bch2_bkey_format_current,
						(struct bkey_packed *) &tmp);
		prt_newline(&buf);

		panic("%s", buf.buf);
	}
}

#else
static inline void bch2_bkey_pack_verify(const struct bkey_packed *packed,
					const struct bkey *unpacked,
					const struct bkey_format_processed *format) {}
#endif

struct pack_state {
	const struct bkey_format *format;
	unsigned		bits;	/* bits remaining in current word */
	u64			w;	/* current word */
	u64			*p;	/* pointer to next word */
};

__always_inline
static struct pack_state pack_state_init(const struct bkey_format *format,
					 struct bkey_packed *k)
{
	u64 *p = high_word(format, k);

	return (struct pack_state) {
		.format	= format,
		.bits	= 64 - high_bit_offset,
		.w	= 0,
		.p	= p,
	};
}

__always_inline
static void pack_state_finish(struct pack_state *state,
			      struct bkey_packed *k)
{
	EBUG_ON(state->p <  k->_data);
	EBUG_ON(state->p >= k->_data + state->format->key_u64s);

	*state->p = state->w;
}

struct unpack_state {
	const struct bkey_format *format;
	unsigned		bits;	/* bits remaining in current word */
	u64			w;	/* current word */
	const u64		*p;	/* pointer to next word */
};

__always_inline
static struct unpack_state unpack_state_init(const struct bkey_format *format,
					     const struct bkey_packed *k)
{
	const u64 *p = high_word(format, k);

	return (struct unpack_state) {
		.format	= format,
		.bits	= 64 - high_bit_offset,
		.w	= *p << high_bit_offset,
		.p	= p,
	};
}

__always_inline
static u64 get_inc_field(struct unpack_state *state, unsigned field)
{
	unsigned bits = state->format->bits_per_field[field];
	u64 v = 0, offset = le64_to_cpu(state->format->field_offset[field]);

	if (bits >= state->bits) {
		v = state->w >> (64 - bits);
		bits -= state->bits;

		state->p = next_word(state->p);
		state->w = *state->p;
		state->bits = 64;
	}

	/* avoid shift by 64 if bits is 0 - bits is never 64 here: */
	v |= (state->w >> 1) >> (63 - bits);
	state->w <<= bits;
	state->bits -= bits;

	return v + offset;
}

__always_inline
static u64 get_aligned_field(const struct bkey_format_processed *f,
			     const struct bkey_packed *in,
			     unsigned field_idx)
{
	u64 v = get_unaligned((u64 *) (((u8 *) in->_data) + f->offset[field_idx]));

	v &= f->mask[field_idx];

	return v + le64_to_cpu(f->f.field_offset[field_idx]);
}

__always_inline
static bool set_inc_field(struct pack_state *state, unsigned field, u64 v)
{
	unsigned bits = state->format->bits_per_field[field];
	u64 offset = le64_to_cpu(state->format->field_offset[field]);

	if (v < offset)
		return false;

	v -= offset;

	if (fls64(v) > bits)
		return false;

	if (bits > state->bits) {
		bits -= state->bits;
		/* avoid shift by 64 if bits is 0 - bits is never 64 here: */
		state->w |= (v >> 1) >> (bits - 1);

		*state->p = state->w;
		state->p = next_word(state->p);
		state->w = 0;
		state->bits = 64;
	}

	state->bits -= bits;
	state->w |= v << state->bits;

	return true;
}

/*
 * Note: does NOT set out->format (we don't know what it should be here!)
 *
 * Also: doesn't work on extents - it doesn't preserve the invariant that
 * if k is packed bkey_start_pos(k) will successfully pack
 */
static bool bch2_bkey_transform_key(const struct bkey_format *out_f,
				   struct bkey_packed *out,
				   const struct bkey_format *in_f,
				   const struct bkey_packed *in)
{
	struct pack_state out_s = pack_state_init(out_f, out);
	struct unpack_state in_s = unpack_state_init(in_f, in);
	u64 *w = out->_data;
	unsigned i;

	*w = 0;

	for (i = 0; i < BKEY_NR_FIELDS; i++)
		if (!set_inc_field(&out_s, i, get_inc_field(&in_s, i)))
			return false;

	/* Can't happen because the val would be too big to unpack: */
	EBUG_ON(in->u64s - in_f->key_u64s + out_f->key_u64s > U8_MAX);

	pack_state_finish(&out_s, out);
	out->u64s	= out_f->key_u64s + in->u64s - in_f->key_u64s;
	out->needs_whiteout = in->needs_whiteout;
	out->type	= in->type;

	return true;
}

bool bch2_bkey_transform(const struct bkey_format *out_f,
			struct bkey_packed *out,
			const struct bkey_format *in_f,
			const struct bkey_packed *in)
{
	if (!bch2_bkey_transform_key(out_f, out, in_f, in))
		return false;

	memcpy_u64s((u64 *) out + out_f->key_u64s,
		    (u64 *) in + in_f->key_u64s,
		    (in->u64s - in_f->key_u64s));
	return true;
}

struct bkey __bch2_bkey_unpack_key(const struct bkey_format_processed *format,
				   const struct bkey_packed *in)
{
	struct bkey out;

	EBUG_ON(format->f.nr_fields != BKEY_NR_FIELDS);
	EBUG_ON(in->u64s < format->f.key_u64s);
	EBUG_ON(in->format != KEY_FORMAT_LOCAL_BTREE);
	EBUG_ON(in->u64s - format->f.key_u64s + BKEY_U64s > U8_MAX);

	out.u64s	= BKEY_U64s + in->u64s - format->f.key_u64s;
	out.format	= KEY_FORMAT_CURRENT;
	out.needs_whiteout = in->needs_whiteout;
	out.type	= in->type;
	out.pad[0]	= 0;

	if (likely(format->aligned)) {
#define x(id, field)	out.field = get_aligned_field(format, in, id);
		bkey_fields()
#undef x
	} else {
		struct unpack_state state = unpack_state_init(&format->f, in);

#define x(id, field)	out.field = get_inc_field(&state, id);
		bkey_fields()
#undef x
	}

	return out;
}

struct bpos __bkey_unpack_pos(const struct bkey_format_processed *format,
			      const struct bkey_packed *in)
{
	struct bpos out;

	EBUG_ON(format->f.nr_fields != BKEY_NR_FIELDS);
	EBUG_ON(in->u64s < format->f.key_u64s);
	EBUG_ON(in->format != KEY_FORMAT_LOCAL_BTREE);

	if (likely(format->aligned)) {
		out.inode	= get_aligned_field(format, in, BKEY_FIELD_INODE);
		out.offset	= get_aligned_field(format, in, BKEY_FIELD_OFFSET);
		out.snapshot	= get_aligned_field(format, in, BKEY_FIELD_SNAPSHOT);
	} else {
		struct unpack_state state = unpack_state_init(&format->f, in);

		out.inode	= get_inc_field(&state, BKEY_FIELD_INODE);
		out.offset	= get_inc_field(&state, BKEY_FIELD_OFFSET);
		out.snapshot	= get_inc_field(&state, BKEY_FIELD_SNAPSHOT);
	}

	return out;
}

/**
 * bch2_bkey_pack_key -- pack just the key, not the value
 */
bool bch2_bkey_pack_key(struct bkey_packed *out, const struct bkey *in,
			const struct bkey_format_processed *format)
{
	struct pack_state state = pack_state_init(&format->f, out);
	u64 *w = out->_data;

	EBUG_ON((void *) in == (void *) out);
	EBUG_ON(format->f.nr_fields != BKEY_NR_FIELDS);
	EBUG_ON(in->format != KEY_FORMAT_CURRENT);

	*w = 0;

#define x(id, field)	if (!set_inc_field(&state, id, in->field)) return false;
	bkey_fields()
#undef x
	pack_state_finish(&state, out);
	out->u64s	= format->f.key_u64s + in->u64s - BKEY_U64s;
	out->format	= KEY_FORMAT_LOCAL_BTREE;
	out->needs_whiteout = in->needs_whiteout;
	out->type	= in->type;

	bch2_bkey_pack_verify(out, in, format);
	return true;
}

/**
 * bch2_bkey_unpack -- unpack the key and the value
 */
void bch2_bkey_unpack(const struct btree *b, struct bkey_i *dst,
		      const struct bkey_packed *src)
{
	__bkey_unpack_key(b, &dst->k, src);

	memcpy_u64s(&dst->v,
		    bkeyp_val(&b->format, src),
		    bkeyp_val_u64s(&b->format, src));
}

/**
 * bch2_bkey_pack -- pack the key and the value
 */
bool bch2_bkey_pack(struct bkey_packed *out, const struct bkey_i *in,
		    const struct bkey_format_processed *format)
{
	struct bkey_packed tmp;

	if (!bch2_bkey_pack_key(&tmp, &in->k, format))
		return false;

	memmove_u64s((u64 *) out + format->f.key_u64s,
		     &in->v,
		     bkey_val_u64s(&in->k));
	memcpy_u64s_small(out, &tmp, format->f.key_u64s);

	return true;
}

__always_inline
static bool set_inc_field_lossy(struct pack_state *state, unsigned field, u64 v)
{
	unsigned bits = state->format->bits_per_field[field];
	u64 offset = le64_to_cpu(state->format->field_offset[field]);
	bool ret = true;

	EBUG_ON(v < offset);
	v -= offset;

	if (fls64(v) > bits) {
		v = ~(~0ULL << bits);
		ret = false;
	}

	if (bits > state->bits) {
		bits -= state->bits;
		state->w |= (v >> 1) >> (bits - 1);

		*state->p = state->w;
		state->p = next_word(state->p);
		state->w = 0;
		state->bits = 64;
	}

	state->bits -= bits;
	state->w |= v << state->bits;

	return ret;
}

#ifdef CONFIG_BCACHEFS_DEBUG
static bool bkey_packed_successor(struct bkey_packed *out,
				  const struct btree *b,
				  struct bkey_packed k)
{
	const struct bkey_format *f = &b->format.f;
	unsigned nr_key_bits = b->nr_key_bits;
	unsigned first_bit, offset;
	u64 *p;

	EBUG_ON(b->nr_key_bits != bkey_format_key_bits(f));

	if (!nr_key_bits)
		return false;

	*out = k;

	first_bit = high_bit_offset + nr_key_bits - 1;
	p = nth_word(high_word(f, out), first_bit >> 6);
	offset = 63 - (first_bit & 63);

	while (nr_key_bits) {
		unsigned bits = min(64 - offset, nr_key_bits);
		u64 mask = (~0ULL >> (64 - bits)) << offset;

		if ((*p & mask) != mask) {
			*p += 1ULL << offset;
			EBUG_ON(bch2_bkey_cmp_packed(b, out, &k) <= 0);
			return true;
		}

		*p &= ~mask;
		p = prev_word(p);
		nr_key_bits -= bits;
		offset = 0;
	}

	return false;
}
#endif

/*
 * Returns a packed key that compares <= in
 *
 * This is used in bset_search_tree(), where we need a packed pos in order to be
 * able to compare against the keys in the auxiliary search tree - and it's
 * legal to use a packed pos that isn't equivalent to the original pos,
 * _provided_ it compares <= to the original pos.
 */
enum bkey_pack_pos_ret bch2_bkey_pack_pos_lossy(struct bkey_packed *out,
					   struct bpos in,
					   const struct btree *b)
{
	const struct bkey_format *f = &b->format.f;
	struct pack_state state = pack_state_init(f, out);
	u64 *w = out->_data;
#ifdef CONFIG_BCACHEFS_DEBUG
	struct bpos orig = in;
#endif
	bool exact = true;
	unsigned i;

	/*
	 * bch2_bkey_pack_key() will write to all of f->key_u64s, minus the 3
	 * byte header, but pack_pos() won't if the len/version fields are big
	 * enough - we need to make sure to zero them out:
	 */
	for (i = 0; i < f->key_u64s; i++)
		w[i] = 0;

	if (unlikely(in.snapshot <
		     le64_to_cpu(f->field_offset[BKEY_FIELD_SNAPSHOT]))) {
		if (!in.offset-- &&
		    !in.inode--)
			return BKEY_PACK_POS_FAIL;
		in.snapshot	= KEY_SNAPSHOT_MAX;
		exact = false;
	}

	if (unlikely(in.offset <
		     le64_to_cpu(f->field_offset[BKEY_FIELD_OFFSET]))) {
		if (!in.inode--)
			return BKEY_PACK_POS_FAIL;
		in.offset	= KEY_OFFSET_MAX;
		in.snapshot	= KEY_SNAPSHOT_MAX;
		exact = false;
	}

	if (unlikely(in.inode <
		     le64_to_cpu(f->field_offset[BKEY_FIELD_INODE])))
		return BKEY_PACK_POS_FAIL;

	if (unlikely(!set_inc_field_lossy(&state, BKEY_FIELD_INODE, in.inode))) {
		in.offset	= KEY_OFFSET_MAX;
		in.snapshot	= KEY_SNAPSHOT_MAX;
		exact = false;
	}

	if (unlikely(!set_inc_field_lossy(&state, BKEY_FIELD_OFFSET, in.offset))) {
		in.snapshot	= KEY_SNAPSHOT_MAX;
		exact = false;
	}

	if (unlikely(!set_inc_field_lossy(&state, BKEY_FIELD_SNAPSHOT, in.snapshot)))
		exact = false;

	pack_state_finish(&state, out);
	out->u64s	= f->key_u64s;
	out->format	= KEY_FORMAT_LOCAL_BTREE;
	out->type	= KEY_TYPE_deleted;

#ifdef CONFIG_BCACHEFS_DEBUG
	if (exact) {
		BUG_ON(bkey_cmp_left_packed(b, out, &orig));
	} else {
		struct bkey_packed successor;

		BUG_ON(bkey_cmp_left_packed(b, out, &orig) >= 0);
		BUG_ON(bkey_packed_successor(&successor, b, *out) &&
		       bkey_cmp_left_packed(b, &successor, &orig) < 0);
	}
#endif

	return exact ? BKEY_PACK_POS_EXACT : BKEY_PACK_POS_SMALLER;
}

void bch2_bkey_format_init(struct bkey_format_state *s)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(s->field_min); i++)
		s->field_min[i] = U64_MAX;

	for (i = 0; i < ARRAY_SIZE(s->field_max); i++)
		s->field_max[i] = 0;

	/* Make sure we can store a size of 0: */
	s->field_min[BKEY_FIELD_SIZE] = 0;
}

void bch2_bkey_format_add_pos(struct bkey_format_state *s, struct bpos p)
{
	unsigned field = 0;

	__bkey_format_add(s, field++, p.inode);
	__bkey_format_add(s, field++, p.offset);
	__bkey_format_add(s, field++, p.snapshot);
}

/*
 * We don't want it to be possible for the packed format to represent fields
 * bigger than a u64... that will cause confusion and issues (like with
 * bkey_packed_successor())
 */
static void set_format_field(struct bkey_format *f, enum bch_bkey_fields i,
			     unsigned bits, u64 offset)
{
	unsigned unpacked_bits = bch2_bkey_format_current.bits_per_field[i];
	u64 unpacked_max = ~((~0ULL << 1) << (unpacked_bits - 1));

	bits = min(bits, unpacked_bits);

	offset = bits == unpacked_bits ? 0 : min(offset, unpacked_max - ((1ULL << bits) - 1));

	f->bits_per_field[i]	= bits;
	f->field_offset[i]	= cpu_to_le64(offset);
}

struct bkey_format bch2_bkey_format_done(struct bkey_format_state *s)
{
	unsigned i, bits = KEY_PACKED_BITS_START;
	struct bkey_format ret = {
		.nr_fields = BKEY_NR_FIELDS,
	};

	for (i = 0; i < ARRAY_SIZE(s->field_min); i++) {
		s->field_min[i] = min(s->field_min[i], s->field_max[i]);

		set_format_field(&ret, i,
				 fls64(s->field_max[i] - s->field_min[i]),
				 s->field_min[i]);

		bits += ret.bits_per_field[i];
	}

	/* allow for extent merging: */
	if (ret.bits_per_field[BKEY_FIELD_SIZE]) {
		ret.bits_per_field[BKEY_FIELD_SIZE] += 4;
		bits += 4;
	}

	ret.key_u64s = DIV_ROUND_UP(bits, 64);

	/* if we have enough spare bits, round fields up to nearest byte */
	bits = ret.key_u64s * 64 - bits;

	for (i = 0; i < ARRAY_SIZE(ret.bits_per_field); i++) {
		unsigned r = round_up(ret.bits_per_field[i], 8) -
			ret.bits_per_field[i];

		if (r <= bits) {
			set_format_field(&ret, i,
					 ret.bits_per_field[i] + r,
					 le64_to_cpu(ret.field_offset[i]));
			bits -= r;
		}
	}

	EBUG_ON(bch2_bkey_format_validate(&ret));
	return ret;
}

const char *bch2_bkey_format_validate(struct bkey_format *f)
{
	unsigned i, bits = KEY_PACKED_BITS_START;

	if (f->nr_fields != BKEY_NR_FIELDS)
		return "incorrect number of fields";

	/*
	 * Verify that the packed format can't represent fields larger than the
	 * unpacked format:
	 */
	for (i = 0; i < f->nr_fields; i++) {
		unsigned unpacked_bits = bch2_bkey_format_current.bits_per_field[i];
		u64 unpacked_max = ~((~0ULL << 1) << (unpacked_bits - 1));
		u64 packed_max = f->bits_per_field[i]
			? ~((~0ULL << 1) << (f->bits_per_field[i] - 1))
			: 0;
		u64 field_offset = le64_to_cpu(f->field_offset[i]);

		if (packed_max + field_offset < packed_max ||
		    packed_max + field_offset > unpacked_max)
			return "field too large";

		bits += f->bits_per_field[i];
	}

	if (f->key_u64s != DIV_ROUND_UP(bits, 64))
		return "incorrect key_u64s";

	return NULL;
}

/*
 * Most significant differing bit
 * Bits are indexed from 0 - return is [0, nr_key_bits)
 */
__pure
unsigned bch2_bkey_greatest_differing_bit(const struct btree *b,
					  const struct bkey_packed *l_k,
					  const struct bkey_packed *r_k)
{
	const u64 *l = high_word(&b->format.f, l_k);
	const u64 *r = high_word(&b->format.f, r_k);
	unsigned nr_key_bits = b->nr_key_bits;
	unsigned word_bits = 64 - high_bit_offset;
	u64 l_v, r_v;

	EBUG_ON(b->nr_key_bits != bkey_format_key_bits(&b->format));

	/* for big endian, skip past header */
	l_v = *l & (~0ULL >> high_bit_offset);
	r_v = *r & (~0ULL >> high_bit_offset);

	while (nr_key_bits) {
		if (nr_key_bits < word_bits) {
			l_v >>= word_bits - nr_key_bits;
			r_v >>= word_bits - nr_key_bits;
			nr_key_bits = 0;
		} else {
			nr_key_bits -= word_bits;
		}

		if (l_v != r_v)
			return fls64(l_v ^ r_v) - 1 + nr_key_bits;

		l = next_word(l);
		r = next_word(r);

		l_v = *l;
		r_v = *r;
		word_bits = 64;
	}

	return 0;
}

/*
 * First set bit
 * Bits are indexed from 0 - return is [0, nr_key_bits)
 */
__pure
unsigned bch2_bkey_ffs(const struct btree *b, const struct bkey_packed *k)
{
	const u64 *p = high_word(&b->format.f, k);
	unsigned nr_key_bits = b->nr_key_bits;
	unsigned ret = 0, offset;

	EBUG_ON(b->nr_key_bits != bkey_format_key_bits(&b->format));

	offset = nr_key_bits;
	while (offset > 64) {
		p = next_word(p);
		offset -= 64;
	}

	offset = 64 - offset;

	while (nr_key_bits) {
		unsigned bits = nr_key_bits + offset < 64
			? nr_key_bits
			: 64 - offset;

		u64 mask = (~0ULL >> (64 - bits)) << offset;

		if (*p & mask)
			return ret + __ffs64(*p & mask) - offset;

		p = prev_word(p);
		nr_key_bits -= bits;
		ret += bits;
		offset = 0;
	}

	return 0;
}

__pure
int __bch2_bkey_cmp_packed_format_checked(const struct bkey_packed *l,
					  const struct bkey_packed *r,
					  const struct btree *b)
{
	return __bch2_bkey_cmp_packed_format_checked_inlined(l, r, b);
}

__pure __flatten
int __bch2_bkey_cmp_left_packed_format_checked(const struct btree *b,
					       const struct bkey_packed *l,
					       const struct bpos *r)
{
	return bpos_cmp(bkey_unpack_pos_format_checked(b, l), *r);
}

__pure __flatten
int bch2_bkey_cmp_packed(const struct btree *b,
			 const struct bkey_packed *l,
			 const struct bkey_packed *r)
{
	return bch2_bkey_cmp_packed_inlined(b, l, r);
}

__pure __flatten
int __bch2_bkey_cmp_left_packed(const struct btree *b,
				const struct bkey_packed *l,
				const struct bpos *r)
{
	const struct bkey *l_unpacked;

	return unlikely(l_unpacked = packed_to_bkey_c(l))
		? bpos_cmp(l_unpacked->p, *r)
		: __bch2_bkey_cmp_left_packed_format_checked(b, l, r);
}

void bch2_bpos_swab(struct bpos *p)
{
	u8 *l = (u8 *) p;
	u8 *h = ((u8 *) &p[1]) - 1;

	while (l < h) {
		swap(*l, *h);
		l++;
		--h;
	}
}

void bch2_bkey_swab_key(const struct bkey_format *_f, struct bkey_packed *k)
{
	const struct bkey_format *f = bkey_packed(k) ? _f : &bch2_bkey_format_current;
	u8 *l = k->key_start;
	u8 *h = (u8 *) (k->_data + f->key_u64s) - 1;

	while (l < h) {
		swap(*l, *h);
		l++;
		--h;
	}
}

#ifdef CONFIG_BCACHEFS_DEBUG
void bch2_bkey_pack_test(void)
{
	struct bkey t = KEY(4134ULL, 1250629070527416633ULL, 0);
	struct bkey_packed p;

	struct bkey_format_processed test_format =
		bch2_bkey_format_postprocess((struct bkey_format) {
			.key_u64s	= 3,
			.nr_fields	= BKEY_NR_FIELDS,
			.bits_per_field = {
				13,
				64,
				32,
			},
		});

	struct unpack_state in_s =
		unpack_state_init(&bch2_bkey_format_current, (void *) &t);
	struct pack_state out_s = pack_state_init(&test_format.f, &p);
	unsigned i;

	for (i = 0; i < out_s.format->nr_fields; i++) {
		u64 a, v = get_inc_field(&in_s, i);

		switch (i) {
#define x(id, field)	case id: a = t.field; break;
	bkey_fields()
#undef x
		default:
			BUG();
		}

		if (a != v)
			panic("got %llu actual %llu i %u\n", v, a, i);

		if (!set_inc_field(&out_s, i, v))
			panic("failed at %u\n", i);
	}

	BUG_ON(!bch2_bkey_pack_key(&p, &t, &test_format));
}
#endif
