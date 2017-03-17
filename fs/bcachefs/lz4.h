#ifndef __BCH_LZ4_H__
#define __BCH_LZ4_H__

int bch2_lz4_decompress(const unsigned char *src, size_t *src_len,
			unsigned char *dest, size_t actual_dest_len);

#endif
