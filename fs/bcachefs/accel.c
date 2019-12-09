/**********************************************************************
  Copyright(c) 2011-2018 Intel Corporation All rights reserved.
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#include "accel.h"
//#include "ec_types.h"

#include <linux/crc64.h>
#include <linux/crc32c.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <asm/fpu/api.h>

#ifdef CONFIG_BCACHEFS_ISAL_BACKEND
#include "isal/include/crc64.h"
#include "isal/include/erasure_code.h"
#endif

#define CAUCHY_RS_MAX 32

/*
 * Generate decode matrix from encode matrix and erasure list
 */
static int gf_gen_decode_matrix_simple(u8 * encode_matrix,
				       u8 * decode_matrix,
				       u8 * invert_matrix,
				       u8 * temp_matrix,
				       u8 * decode_index, int * frag_err_list, int nerrs, int k,
				       int m);

static u64 kernel_crc64(u64 crc, const void* p, size_t len) {
	return crc64_be(crc, p, len);
}

static u64 isal_crc64(u64 crc, const void* p, size_t len) { 
	u64 state = ~crc;

	kernel_fpu_begin();
	state = crc64_ecma_norm(state, (const unsigned char*)p, len);
	kernel_fpu_end();

	return ~state;
}

u64 accel_crc64(u64 crc, const void* p, size_t len) {
	#ifdef CONFIG_BCACHEFS_ISAL_BACKEND
	return isal_crc64(crc, p, len);
	#else
	return kernel_crc64(crc, p, len);
	#endif
}

u32 accel_crc32c(u32 crc, const void* p, size_t len) {
	// Kernel already provides carryless-multiply CRC32C
	// on relevant architectures.
	return crc32c(crc, p, len);
	
	// TODO: Ensure ARM64 is calling NEON code. crc32-ce 
	// seems to be missing from the ARM64 crypto folder.
}

void accel_erasure_encode(int nd, int np, size_t size, void **v)
{
	u8 *encode;
	u8 *tables;
	int nm = nd + np;

	BUG_ON(nm > CAUCHY_RS_MAX);

	if(np == 0) {
		return;
	}

	// TODO: Pre allocate matricies to ensure function will never fail
	// TODO: Cache/pool matricies to increase encode performance
	encode = kmalloc(nm * nd, GFP_KERNEL);
	tables = kmalloc(nd * np * 32, GFP_KERNEL);
	BUG_ON(encode == NULL);
	BUG_ON(tables == NULL);

	gf_gen_cauchy1_matrix(encode, nm, nd);
	ec_init_tables(nd, np, &encode[nd * nd], tables);

	kernel_fpu_begin();
	ec_encode_data(size, nd, np, tables, (unsigned char**)v, (unsigned char**)&v[nd]);
	kernel_fpu_end();

	kfree(encode);
	kfree(tables);
}

void accel_erasure_decode(int nr, int *ir, int nd, int np, size_t size, void **v)
{
	u8 *encode;
	u8 *decode;
	u8 *inverse;
	u8 *scratch;
	u8 *tables;
	u8 decode_index[CAUCHY_RS_MAX];
	u8 *recover_srcs[CAUCHY_RS_MAX];
	u8 *recover_outp[CAUCHY_RS_MAX];

	int nm = nd + np;
	int ret;
	int i;
	

	BUG_ON(nm > CAUCHY_RS_MAX);

	if(np == 0 || nr == 0) {
		return;
	}

	// TODO: Pre allocate matricies to ensure function will never fail
	// TODO: Cache/pool matricies to increase decode performance
	encode = kmalloc(nm * nd, GFP_KERNEL);
	decode = kmalloc(nm * nd, GFP_KERNEL);
	inverse = kmalloc(nm * nd, GFP_KERNEL);
	scratch = kmalloc(nm * nd, GFP_KERNEL);
	tables = kmalloc(nd * np * 32, GFP_KERNEL);
	BUG_ON(encode == NULL);
	BUG_ON(decode == NULL);
	BUG_ON(inverse == NULL);
	BUG_ON(scratch == NULL);
	BUG_ON(tables == NULL);

	gf_gen_cauchy1_matrix(encode, nm, nd);
	ret = gf_gen_decode_matrix_simple(encode, decode, inverse, scratch, decode_index, ir, nr, nd, nm);
	BUG_ON(ret != 0); // Cauchy matricies should always be invertible.
	ec_init_tables(nd, nr, decode, tables);

	// Pack array pointers as list of fragments
	for (i = 0; i < nd; i++)
		recover_srcs[i] = v[decode_index[i]];
	for (i = 0; i < nr; i++)
		recover_outp[i] = v[ir[i]];

	kernel_fpu_begin();
	ec_encode_data(size, nd, nr, tables, recover_srcs, recover_outp);
	kernel_fpu_end();

	kfree(encode);
	kfree(decode);
	kfree(inverse);
	kfree(scratch);
	kfree(tables);
}

/*
 * Generate decode matrix from encode matrix and erasure list
 * Implementation sourced from Intel ISA-L simple example. 
 */
static int gf_gen_decode_matrix_simple(u8 * encode_matrix,
				       u8 * decode_matrix,
				       u8 * invert_matrix,
				       u8 * temp_matrix,
				       u8 * decode_index, int * frag_err_list, int nerrs, int k,
				       int m)
{
	int i, j, p, r;
	int nsrcerrs = 0;
	u8 s, *b = temp_matrix;
	u8 frag_in_err[CAUCHY_RS_MAX];

	memset(frag_in_err, 0, sizeof(frag_in_err));

	// Order the fragments in erasure for easier sorting
	for (i = 0; i < nerrs; i++) {
		if (frag_err_list[i] < k)
			nsrcerrs++;
		frag_in_err[frag_err_list[i]] = 1;
	}

	// Construct b (matrix that encoded remaining frags) by removing erased rows
	for (i = 0, r = 0; i < k; i++, r++) {
		while (frag_in_err[r])
			r++;
		for (j = 0; j < k; j++)
			b[k * i + j] = encode_matrix[k * r + j];
		decode_index[i] = r;
	}

	// Invert matrix to get recovery matrix
	if (gf_invert_matrix(b, invert_matrix, k) < 0)
		return -1;

	// Get decode matrix with only wanted recovery rows
	for (i = 0; i < nerrs; i++) {
		if (frag_err_list[i] < k)	// A src err
			for (j = 0; j < k; j++)
				decode_matrix[k * i + j] =
				    invert_matrix[k * frag_err_list[i] + j];
	}

	// For non-src (parity) erasures need to multiply encode matrix * invert
	for (p = 0; p < nerrs; p++) {
		if (frag_err_list[p] >= k) {	// A parity err
			for (i = 0; i < k; i++) {
				s = 0;
				for (j = 0; j < k; j++)
					s ^= gf_mul(invert_matrix[j * k + i],
						    encode_matrix[k * frag_err_list[p] + j]);
				decode_matrix[k * p + i] = s;
			}
		}
	}
	return 0;
}


static const int MB = 1024 * 1024;
static const int LARGE_BLOCK = 2 * MB; // Filesystem large IOs (Media etc)
static const int SMALL_BLOCK = 4096; // Filesystem small IOs (Databases etc)
static const int CACHE_THRASH = 512 * MB; // Larger than Epyc ROME L3 Cache
static const int WARMUP_ITER = 3;
static const int BENCH_ITER = 5;

static const char* csum_test_vecs[] = { 
	"",
	"The quick brown fox jumps over the lazy dog.",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
};
static const u64 crc64_test_refs[] = {
	0x0000000000000000ull,
	0xea6939e68ade7f25ull,
	0x5ca18585b92c58b9ull
};
static const int num_csm_test_vecs = sizeof(csum_test_vecs) / sizeof(const char*);

static void test_vec_crc64(u64(*f)(u64, const void*, size_t), const char* name) {
	int i;
	u64 res;

	for(i = 0; i < num_csm_test_vecs; i++) {
		res = f(0, csum_test_vecs[i], strlen(csum_test_vecs[i]));

		if(res != crc64_test_refs[i]) {
			printk("%s: test failed. \"%s\" was %#010llx expected %#010llx \n", name, csum_test_vecs[i], res, crc64_test_refs[i]);
		}
	}
}

static void bench_crc64(u64(*f)(u64, const void*, size_t), size_t bench_size, const char* name) {
	char* buf = vmalloc(bench_size);
	int i;
	u64 sum = 0;

	for(i = 0; i < bench_size; i++) {
		buf[i] = (char)i;
	}

	for(i = 0; i < WARMUP_ITER; i++) {
		f(~0, buf, bench_size);
	}

	for(i = 0; i < BENCH_ITER; i++) {
		u64 begin;
		u64 end;
		u64 diff;

		begin = ktime_get_ns();
		f(~0, buf, bench_size);
		end = ktime_get_ns();

		diff = end - begin;
		sum += diff;
	}

	sum /= BENCH_ITER;
	printk("%s: %llu ns\n", name, sum);

	vfree(buf);
}


int accel_benchmark(const char* prim) {
	int crc64 = 0;
	int ret = -EINVAL;

	if(strcmp(prim, "all") == 0) {
		crc64 = 1;
		ret = 0;
	} else if (strcmp(prim, "crc64") == 0) {
		crc64 = 1;
		ret = 0;
	}

	if(crc64) {
		test_vec_crc64(&kernel_crc64, "KERNEL CRC64");

		bench_crc64(&kernel_crc64, CACHE_THRASH, "KERNEL CRC64 512MB");
		bench_crc64(&kernel_crc64, LARGE_BLOCK, "KERNEL CRC64 2MB");
		bench_crc64(&kernel_crc64, SMALL_BLOCK, "KERNEL CRC64 4KB");

		#ifdef CONFIG_BCACHEFS_ISAL_BACKEND
		test_vec_crc64(&isal_crc64, "ISAL CRC64");


		bench_crc64(&isal_crc64, CACHE_THRASH, "ISAL CRC64 512MB");
		bench_crc64(&isal_crc64, LARGE_BLOCK, "ISAL CRC64 2MB");
		bench_crc64(&isal_crc64, SMALL_BLOCK, "ISAL CRC64 4KB");
		#endif
	}

	return ret;
}
