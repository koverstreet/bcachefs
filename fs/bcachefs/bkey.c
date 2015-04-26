
#include <linux/kernel.h>

#include "bkey.h"

int bch_bkey_to_text(char *buf, size_t size, const struct bkey *k)
{
	char *out = buf, *end = buf + size;

#define p(...)	(out += scnprintf(out, end - out, __VA_ARGS__))

	p("u64s %u format %u %llu:%llu snap %u len %u ver %u",
	  k->u64s, k->format, k->p.inode, k->p.offset,
	  k->p.snapshot, k->size, k->version);

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
