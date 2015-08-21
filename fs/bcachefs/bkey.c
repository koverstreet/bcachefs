
#include <linux/kernel.h>

#include "bkey.h"

int bch_bkey_to_text(char *buf, size_t size, const struct bkey *k)
{
	char *out = buf, *end = buf + size;

#define p(...)	(out += scnprintf(out, end - out, __VA_ARGS__))

	p("%llu:%llu snap %llu len %llu ver %llu",
	  KEY_INODE(k), KEY_OFFSET(k), KEY_SNAPSHOT(k),
	  KEY_SIZE(k), KEY_VERSION(k));

	if (KEY_DELETED(k))
		p(" deleted");
	if (KEY_WIPED(k))
		p(" wiped");
#undef p

	return out - buf;
}
