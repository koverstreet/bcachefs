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

#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <asm/fpu/api.h>

#ifdef CONFIG_BCACHEFS_ISAL_BACKEND
#include "isal/erasure_code/erasure_code.h"
#endif

#define CAUCHY_RS_MAX 16
#define MAX_PARITY 4

static int gf_gen_decode_matrix_simple(u8 * encode_matrix,
				       u8 * decode_matrix,
				       u8 * invert_matrix,
				       u8 * temp_matrix,
				       u8 * decode_index, int * frag_err_list, int nerrs, int k,
				       int m);

void accel_erasure_encode(int nd, int np, size_t size, void **v)
{
	u8 *encode;
	u8 *tables;
	int nm = nd + np;
	u64 start;
	u64 end;

	printk("Encode %i %i %lu\n", nd, np, size);

	start = ktime_get_ns();
	BUG_ON(np > MAX_PARITY);
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

	gf_gen_rs_matrix(encode, nm, nd);
	ec_init_tables(nd, np, &encode[nd * nd], tables);

	kernel_fpu_begin();
	ec_encode_data(size, nd, np, tables, (unsigned char**)v, (unsigned char**)&v[nd]);
	kernel_fpu_end();

	kfree(encode);
	kfree(tables);

	end = ktime_get_ns();
	printk("End %llu \n", end - start);
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

	gf_gen_rs_matrix(encode, nm, nd);
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