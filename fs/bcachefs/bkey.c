
#define pr_fmt(fmt) "bcache: %s() " fmt "\n", __func__

#include <linux/kernel.h>

#include "bkey.h"
#include "bset.h"
#include "util.h"

const struct bkey_format bch_bkey_format_current = BKEY_FORMAT_CURRENT;

#ifdef CONFIG_BCACHEFS_DEBUG

static void to_binary(char *out, u64 in, unsigned nr_bits)
{
	unsigned i;

	for (i = 0; i < nr_bits; i++)
		out[i] = test_bit(nr_bits - 1 - i, (void *) &in) ? '1' : '0';
	out[nr_bits] = '\0';
}

static void bch_bkey_pack_verify(const struct bkey_packed *packed,
				 const struct bkey *unpacked,
				 const struct bkey_format *format)
{
	struct bkey tmp;

	BUG_ON(bkeyp_val_u64s(format, packed) !=
	       bkey_val_u64s(unpacked));

	BUG_ON(packed->u64s < bkeyp_key_u64s(format, packed));

	tmp = bkey_unpack_key(format, packed);

	if (memcmp(&tmp, unpacked, sizeof(struct bkey))) {
		char buf1[160], buf2[160];
		char buf3[80], buf4[80];

		bch_bkey_to_text(buf1, sizeof(buf1), unpacked);
		bch_bkey_to_text(buf2, sizeof(buf2), &tmp);
		to_binary(buf3, unpacked->p.offset, 64);
		to_binary(buf4, *high_word(format, packed), 64);

		panic("keys differ: format u64s %u fields %u %u %u %u %u\n%s\n%s\n%s\n%s\n",
		      format->key_u64s,
		      format->bits_per_field[0],
		      format->bits_per_field[1],
		      format->bits_per_field[2],
		      format->bits_per_field[3],
		      format->bits_per_field[4],
		      buf1, buf2, buf3, buf4);
	}
}

#else
static inline void bch_bkey_pack_verify(const struct bkey_packed *packed,
					const struct bkey *unpacked,
					const struct bkey_format *format) {}
#endif

int bch_bkey_to_text(char *buf, size_t size, const struct bkey *k)
{
	char *out = buf, *end = buf + size;

#define p(...)	(out += scnprintf(out, end - out, __VA_ARGS__))

	p("u64s %u type %u %llu:%llu snap %u len %u ver %u",
	  k->u64s, k->type, k->p.inode, k->p.offset,
	  k->p.snapshot, k->size, k->version);

	BUG_ON(bkey_packed(k));

	switch (k->type) {
	case KEY_TYPE_DELETED:
		p(" deleted");
		break;
	case KEY_TYPE_DISCARD:
		p(" discard");
		break;
	case KEY_TYPE_ERROR:
		p(" error");
		break;
	case KEY_TYPE_COOKIE:
		p(" cookie");
		break;
	}
#undef p

	return out - buf;
}

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
static void pack_state_finish(struct pack_state *state)
{
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
		.w	= *p >> high_bit_offset,
		.p	= p,
	};
}

__always_inline
static u64 get_inc_field(struct unpack_state *state, unsigned field)
{
	unsigned bits = state->format->bits_per_field[field];
	u64 v = 0, offset = state->format->field_offset[field];

	if (bits >= state->bits) {
		v = state->w >> (64 - bits);
		bits -= state->bits;

		state->p = next_word(state->p);
		state->w = *state->p;
		state->bits = 64;
	}

	if (likely(bits)) {
		/* avoid shift by 64 if bits is 0 */
		v |= state->w >> (64 - bits);
		state->bits -= bits;
		state->w <<= bits;
	}

	return v + offset;
}

__always_inline
static bool set_inc_field(struct pack_state *state, unsigned field, u64 v)
{
	unsigned bits = state->format->bits_per_field[field];
	u64 offset = state->format->field_offset[field];

	if (v < offset)
		return false;

	v -= offset;

	if (fls64(v) > bits)
		return false;

	if (bits >= state->bits) {
		bits -= state->bits;
		state->w |= v >> bits;

		*state->p = state->w;
		state->p = next_word(state->p);
		state->w = 0;
		state->bits = 64;
	}

	if (likely(bits)) {
		state->bits -= bits;
		state->w |= v << state->bits;
	}

	return true;
}

/*
 * Note: does NOT set out->format
 */
static bool bch_bkey_transform_key(const struct bkey_format *out_f,
				   struct bkey_packed *out,
				   const struct bkey_format *in_f,
				   const struct bkey_packed *in)
{
	struct pack_state out_s = pack_state_init(out_f, out);
	struct unpack_state in_s = unpack_state_init(in_f, in);
	unsigned i;

	for (i = 0; i < BKEY_NR_FIELDS; i++)
		if (!set_inc_field(&out_s, i, get_inc_field(&in_s, i)))
			return false;

	pack_state_finish(&out_s);
	out->u64s	= out_f->key_u64s + in->u64s - in_f->key_u64s;
	out->type	= in->type;

	return true;
}

bool bch_bkey_transform(const struct bkey_format *out_f,
			struct bkey_packed *out,
			const struct bkey_format *in_f,
			const struct bkey_packed *in)
{
	if (!bch_bkey_transform_key(out_f, out, in_f, in))
		return false;

	memcpy((u64 *) out + out_f->key_u64s,
	       (u64 *) in + in_f->key_u64s,
	       (in->u64s - in_f->key_u64s) * sizeof(u64));
	return true;
}

static struct bkey __bkey_unpack_key(const struct bkey_format *format,
				     const struct bkey_packed *in)
{
	struct unpack_state state = unpack_state_init(format, in);
	struct bkey out;

	EBUG_ON(format->nr_fields != 5);
	EBUG_ON(in->u64s < format->key_u64s);
	EBUG_ON(in->format != KEY_FORMAT_LOCAL_BTREE);

	out.u64s	= BKEY_U64s + in->u64s - format->key_u64s;
	out.format	= KEY_FORMAT_CURRENT;
	out.type	= in->type;
	out.pad[0]	= 0;
	out.p.inode	= get_inc_field(&state, BKEY_FIELD_INODE);
	out.p.offset	= get_inc_field(&state, BKEY_FIELD_OFFSET);
	out.p.snapshot	= get_inc_field(&state, BKEY_FIELD_SNAPSHOT);
	out.size	= get_inc_field(&state, BKEY_FIELD_SIZE);
	out.version	= get_inc_field(&state, BKEY_FIELD_VERSION);

	return out;
}

static struct bpos __bkey_unpack_pos(const struct bkey_format *format,
				     const struct bkey_packed *in)
{
	struct unpack_state state = unpack_state_init(format, in);
	struct bpos out;

	EBUG_ON(format->nr_fields != 5);
	EBUG_ON(in->u64s < format->key_u64s);
	EBUG_ON(in->format != KEY_FORMAT_LOCAL_BTREE);

	out.inode	= get_inc_field(&state, BKEY_FIELD_INODE);
	out.offset	= get_inc_field(&state, BKEY_FIELD_OFFSET);
	out.snapshot	= get_inc_field(&state, BKEY_FIELD_SNAPSHOT);

	return out;
}

/**
 * bkey_pack_key -- pack just the key, not the value
 */
bool bkey_pack_key(struct bkey_packed *out, const struct bkey *in,
		   const struct bkey_format *format)
{
	struct pack_state state = pack_state_init(format, out);

	EBUG_ON(format->nr_fields != 5);
	EBUG_ON(in->format != KEY_FORMAT_CURRENT);

	if (!set_inc_field(&state, BKEY_FIELD_INODE,	in->p.inode) ||
	    !set_inc_field(&state, BKEY_FIELD_OFFSET,	in->p.offset) ||
	    !set_inc_field(&state, BKEY_FIELD_SNAPSHOT,	in->p.snapshot) ||
	    !set_inc_field(&state, BKEY_FIELD_SIZE,	in->size) ||
	    !set_inc_field(&state, BKEY_FIELD_VERSION,	in->version))
		return false;

	pack_state_finish(&state);
	out->u64s	= format->key_u64s + in->u64s - BKEY_U64s;
	out->format	= KEY_FORMAT_LOCAL_BTREE;
	out->type	= in->type;

	bch_bkey_pack_verify(out, in, format);
	return true;
}

/*
 * Alternate implementations using bkey_format_transform() - unfortunately, too
 * slow
 */
#if 0
struct bkey __bkey_unpack_key(const struct bkey_format *format,
			      const struct bkey_packed *in)
{
	struct bkey out;
	bool s;

	EBUG_ON(format->nr_fields != 5);
	EBUG_ON(in->u64s < format->key_u64s);
	EBUG_ON(in->format != KEY_FORMAT_LOCAL_BTREE);

	s = bch_bkey_transform_key(&bch_bkey_format_current, (void *) &out,
				   format, in);
	EBUG_ON(!s);

	out.format = KEY_FORMAT_CURRENT;

	return out;
}

bool bkey_pack_key(struct bkey_packed *out, const struct bkey *in,
		   const struct bkey_format *format)
{
	EBUG_ON(format->nr_fields != 5);
	EBUG_ON(in->format != KEY_FORMAT_CURRENT);

	if (!bch_bkey_transform_key(format, out,
				    &bch_bkey_format_current, (void *) in))
		return false;

	out->format = KEY_FORMAT_LOCAL_BTREE;

	bch_bkey_pack_verify(out, in, format);
	return true;
}
#endif

/**
 * bkey_unpack_key -- unpack just the key, not the value
 */
__attribute__((flatten))
struct bkey bkey_unpack_key(const struct bkey_format *format,
			    const struct bkey_packed *src)
{
	return likely(bkey_packed(src))
		? __bkey_unpack_key(format, src)
		: *packed_to_bkey_c(src);
}

/**
 * bkey_unpack -- unpack the key and the value
 */
void bkey_unpack(struct bkey_i *dst,
		 const struct bkey_format *format,
		 const struct bkey_packed *src)
{
	dst->k = bkey_unpack_key(format, src);

	memcpy(&dst->v,
	       bkeyp_val(format, src),
	       bkeyp_val_bytes(format, src));
}

/**
 * bkey_pack -- pack the key and the value
 */
bool bkey_pack(struct bkey_packed *out, const struct bkey_i *in,
	       const struct bkey_format *format)
{
	struct bkey_packed tmp;

	if (!bkey_pack_key(&tmp, &in->k, format))
		return false;

	memmove((u64 *) out + format->key_u64s,
		&in->v,
		bkey_val_bytes(&in->k));
	memcpy(out, &tmp,
	       format->key_u64s * sizeof(u64));

	return true;
}

__always_inline
static bool set_inc_field_lossy(struct pack_state *state, unsigned field, u64 v)
{
	unsigned bits = state->format->bits_per_field[field];
	u64 offset = state->format->field_offset[field];
	bool ret = true;

	EBUG_ON(v < offset);
	v -= offset;

	if (fls64(v) > bits) {
		v = ~(~0ULL << bits);
		ret = false;
	}

	if (bits >= state->bits) {
		bits -= state->bits;
		state->w |= v >> bits;

		*state->p = state->w;
		state->p = next_word(state->p);
		state->bits = 64;
		state->w = 0;
	}

	if (likely(bits)) {
		/* avoid shift by 64 */
		state->bits -= bits;
		state->w |= v << state->bits;
	}

	return ret;
}

#ifdef CONFIG_BCACHEFS_DEBUG
static bool bkey_packed_successor(struct bkey_packed *out,
				  const struct bkey_format *format,
				  struct bkey_packed k)
{
	u64 *p = high_word(format, out);
	unsigned nr_key_bits = bkey_format_key_bits(format);
	unsigned offset;

	*out = k;

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

		if ((*p & mask) != mask) {
			*p += 1ULL << offset;
			EBUG_ON(__bkey_cmp_packed(format, out, &k) <= 0);
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
enum bkey_pack_pos_ret bkey_pack_pos_lossy(struct bkey_packed *out,
					   struct bpos in,
					   const struct bkey_format *format)
{
	struct pack_state state = pack_state_init(format, out);
#ifdef CONFIG_BCACHEFS_DEBUG
	struct bpos orig = in;
#endif
	bool exact = true;

	if (unlikely(in.snapshot < format->field_offset[BKEY_FIELD_SNAPSHOT])) {
		if (!in.offset-- &&
		    !in.inode--)
			return BKEY_PACK_POS_FAIL;
		in.snapshot	= KEY_SNAPSHOT_MAX;
		exact = false;
	}

	if (unlikely(in.offset < format->field_offset[BKEY_FIELD_OFFSET])) {
		if (!in.inode--)
			return BKEY_PACK_POS_FAIL;
		in.offset	= KEY_OFFSET_MAX;
		in.snapshot	= KEY_SNAPSHOT_MAX;
		exact = false;
	}

	if (unlikely(in.inode < format->field_offset[BKEY_FIELD_INODE]))
		return BKEY_PACK_POS_FAIL;

	if (!set_inc_field_lossy(&state, BKEY_FIELD_INODE, in.inode)) {
		in.offset	= KEY_OFFSET_MAX;
		in.snapshot	= KEY_SNAPSHOT_MAX;
		exact = false;
	}

	if (!set_inc_field_lossy(&state, BKEY_FIELD_OFFSET, in.offset)) {
		in.snapshot	= KEY_SNAPSHOT_MAX;
		exact = false;
	}

	if (!set_inc_field_lossy(&state, BKEY_FIELD_SNAPSHOT, in.snapshot))
		exact = false;

	pack_state_finish(&state);
	out->u64s	= format->key_u64s;
	out->format	= KEY_FORMAT_LOCAL_BTREE;
	out->type	= KEY_TYPE_DELETED;

#ifdef CONFIG_BCACHEFS_DEBUG
	if (exact) {
		BUG_ON(bkey_cmp_left_packed(format, out, orig));
	} else {
		struct bkey_packed successor;

		BUG_ON(bkey_cmp_left_packed(format, out, orig) >= 0);
		BUG_ON(bkey_packed_successor(&successor, format, *out) &&
		       bkey_cmp_left_packed(format, &successor, orig) < 0);
	}
#endif

	return exact ? BKEY_PACK_POS_EXACT : BKEY_PACK_POS_SMALLER;
}

void bch_bkey_format_init(struct bkey_format_state *s)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(s->field_min); i++)
		s->field_min[i] = U64_MAX;

	for (i = 0; i < ARRAY_SIZE(s->field_max); i++)
		s->field_max[i] = 0;
}

static void __bkey_format_add(struct bkey_format_state *s,
			      unsigned field, u64 v)
{
	s->field_min[field] = min(s->field_min[field], v);
	s->field_max[field] = max(s->field_max[field], v);
}

/*
 * Changes @format so that @k can be successfully packed with @format
 */
void bch_bkey_format_add_key(struct bkey_format_state *s, struct bkey *k)
{
	unsigned field = 0;

	__bkey_format_add(s, field++, k->p.inode);
	__bkey_format_add(s, field++, k->p.offset);
	__bkey_format_add(s, field++, k->p.snapshot);
	__bkey_format_add(s, field++, k->size);
	__bkey_format_add(s, field++, k->version);
	EBUG_ON(field != BKEY_NR_FIELDS);
}

void bch_bkey_format_add_pos(struct bkey_format_state *s, struct bpos p)
{
	unsigned field = 0;

	__bkey_format_add(s, field++, p.inode);
	__bkey_format_add(s, field++, p.offset);
	__bkey_format_add(s, field++, p.snapshot);
}

struct bkey_format bch_bkey_format_done(struct bkey_format_state *s)
{
	unsigned i, bits = KEY_PACKED_BITS_START;
	struct bkey_format ret = {
		.nr_fields = BKEY_NR_FIELDS,
	};

	for (i = 0; i < ARRAY_SIZE(s->field_min); i++) {
		ret.field_offset[i]	= min(s->field_min[i], s->field_max[i]);
		ret.bits_per_field[i]	= fls64(s->field_max[i] -
						ret.field_offset[i]);

		bits += ret.bits_per_field[i];
	}

	ret.key_u64s = DIV_ROUND_UP(bits, 64);

	return ret;
}

const char *bch_bkey_format_validate(struct bkey_format *f)
{
	unsigned i, bits = KEY_PACKED_BITS_START;

	if (f->nr_fields != BKEY_NR_FIELDS)
		return "invalid format: incorrect number of fields";

	for (i = 0; i < f->nr_fields; i++) {
		if (f->bits_per_field[i] > 64)
			return "invalid format: field too large";

		bits += f->bits_per_field[i];
	}

	if (f->key_u64s != DIV_ROUND_UP(bits, 64))
		return "invalid format: incorrect key_u64s";

	return NULL;
}

/* Most significant differing bit */
unsigned bkey_greatest_differing_bit(const struct bkey_format *format,
				     const struct bkey_packed *l_k,
				     const struct bkey_packed *r_k)
{
	const u64 *l = high_word(format, l_k);
	const u64 *r = high_word(format, r_k);
	unsigned nr_key_bits = bkey_format_key_bits(format);
	u64 l_v, r_v;

	/* for big endian, skip past header */
	nr_key_bits += high_bit_offset;
	l_v = *l & (~0ULL >> high_bit_offset);
	r_v = *r & (~0ULL >> high_bit_offset);

	while (1) {
		if (nr_key_bits < 64) {
			l_v >>= 64 - nr_key_bits;
			r_v >>= 64 - nr_key_bits;
			nr_key_bits = 0;
		} else {
			nr_key_bits -= 64;
		}

		if (l_v != r_v)
			return fls64(l_v ^ r_v) + nr_key_bits;

		if (!nr_key_bits)
			return 0;

		l = next_word(l);
		r = next_word(r);

		l_v = *l;
		r_v = *r;
	}
}

unsigned bkey_ffs(const struct bkey_format *format,
		  const struct bkey_packed *k)
{
	const u64 *p = high_word(format, k);
	unsigned nr_key_bits = bkey_format_key_bits(format);
	unsigned ret = 0, offset;

	offset = nr_key_bits;
	while (offset >= 64) {
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

static int __bkey_cmp_bits(unsigned nr_key_bits, const u64 *l, const u64 *r)
{
	u64 l_v, r_v;

	if (!nr_key_bits)
		return 0;

	/* for big endian, skip past header */
	nr_key_bits += high_bit_offset;
	l_v = *l & (~0ULL >> high_bit_offset);
	r_v = *r & (~0ULL >> high_bit_offset);

	while (1) {
		if (nr_key_bits < 64) {
			l_v >>= 64 - nr_key_bits;
			r_v >>= 64 - nr_key_bits;
			nr_key_bits = 0;
		} else {
			nr_key_bits -= 64;
		}

		if (l_v != r_v)
			return l_v < r_v ? -1 : 1;

		if (!nr_key_bits)
			return 0;

		l = next_word(l);
		r = next_word(r);

		l_v = *l;
		r_v = *r;
	}
}

/*
 * Would like to use this if we can make __bkey_cmp_bits() fast enough, it'll be
 * a decent reduction in code size
 */
#if 0
static int bkey_cmp_verify(const struct bkey *l, const struct bkey *r)
{
	if (l->p.inode != r->p.inode)
		return l->p.inode < r->p.inode ? -1 : 1;

	if (l->p.offset != r->p.offset)
		return l->p.offset < r->p.offset ? -1 : 1;

	if (l->p.snapshot != r->p.snapshot)
		return l->p.snapshot < r->p.snapshot ? -1 : 1;

	return 0;
}

int bkey_cmp(const struct bkey *l, const struct bkey *r)
{
	int ret;

	EBUG_ON(bkey_packed(l) || bkey_packed(r));

	ret = __bkey_cmp_bits((sizeof(l->inode) +
			       sizeof(l->offset) +
			       sizeof(l->snapshot)) * BITS_PER_BYTE,
			      __high_word(BKEY_U64s, l),
			      __high_word(BKEY_U64s, r));

	BUG_ON(ret != bkey_cmp_verify(l, r));

	return ret;
}
#endif

int __bkey_cmp_packed(const struct bkey_format *f,
		      const struct bkey_packed *l,
		      const struct bkey_packed *r)
{
	int ret;

	EBUG_ON(!bkey_packed(l) || !bkey_packed(r));

	ret = __bkey_cmp_bits(bkey_format_key_bits(f),
			      high_word(f, l),
			      high_word(f, r));

	EBUG_ON(ret != bkey_cmp(bkey_unpack_key(f, l).p,
				bkey_unpack_key(f, r).p));
	return ret;
}

__attribute__((flatten))
int __bkey_cmp_left_packed(const struct bkey_format *format,
			   const struct bkey_packed *l, struct bpos r)
{
	return bkey_cmp(__bkey_unpack_pos(format, l), r);
}

#ifdef CONFIG_BCACHEFS_DEBUG
void bkey_pack_test(void)
{
	struct bkey t = KEY(4134ULL, 1250629070527416633ULL, 0);
	struct bkey_packed p;

	struct bkey_format test_format = {
		.key_u64s	= 2,
		.nr_fields	= 5,
		.bits_per_field = {
			13,
			64,
		},
	};

	struct unpack_state in_s =
		unpack_state_init(&bch_bkey_format_current, (void *) &t);
	struct pack_state out_s = pack_state_init(&test_format, &p);
	unsigned i;

	if (in_s.p != &t.p.inode)
		panic("input state wrong, p %p should be %p\n",
		      in_s.p, &t.p.inode);

	for (i = 0; i < out_s.format->nr_fields; i++) {
		u64 a, v = get_inc_field(&in_s, i);

		switch (i) {
		case 0:
			a = t.p.inode;
			break;
		case 1:
			a = t.p.offset;
			break;
		case 2:
			a = t.p.snapshot;
			break;
		case 3:
			a = t.size;
			break;
		case 4:
			a = t.version;
			break;
		default:
			BUG();
		}

		BUG_ON(a != v);
		if (a != v)
			panic("got %llu actual %llu i %u\n", v, a, i);

		if (!set_inc_field(&out_s, i, v))
			panic("failed at %u\n", i);
	}

	BUG_ON(!bkey_pack_key(&p, &t, &test_format));
}
#endif
