/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Hantro VPU codec driver
 *
 * Copyright 2018 Google LLC.
 *	Tomasz Figa <tfiga@chromium.org>
 */

#ifndef HANTRO_HW_H_
#define HANTRO_HW_H_

#include <linux/interrupt.h>
#include <linux/v4l2-controls.h>
#include <media/v4l2-ctrls.h>
#include <media/videobuf2-core.h>

#define DEC_8190_ALIGN_MASK	0x07U

#define MB_DIM			16
#define MB_WIDTH(w)		DIV_ROUND_UP(w, MB_DIM)
#define MB_HEIGHT(h)		DIV_ROUND_UP(h, MB_DIM)

#define NUM_REF_PICTURES	(V4L2_HEVC_DPB_ENTRIES_NUM_MAX + 1)

struct hantro_dev;
struct hantro_ctx;
struct hantro_buf;
struct hantro_variant;

/**
 * struct hantro_aux_buf - auxiliary DMA buffer for hardware data
 *
 * @cpu:	CPU pointer to the buffer.
 * @dma:	DMA address of the buffer.
 * @size:	Size of the buffer.
 * @attrs:	Attributes of the DMA mapping.
 */
struct hantro_aux_buf {
	void *cpu;
	dma_addr_t dma;
	size_t size;
	unsigned long attrs;
};

/**
 * struct hantro_jpeg_enc_hw_ctx
 *
 * @bounce_buffer:	Bounce buffer
 */
struct hantro_jpeg_enc_hw_ctx {
	struct hantro_aux_buf bounce_buffer;
};

/* Max. number of entries in the DPB (HW limitation). */
#define HANTRO_H264_DPB_SIZE		16

/**
 * struct hantro_h264_dec_ctrls
 *
 * @decode:	Decode params
 * @scaling:	Scaling info
 * @sps:	SPS info
 * @pps:	PPS info
 */
struct hantro_h264_dec_ctrls {
	const struct v4l2_ctrl_h264_decode_params *decode;
	const struct v4l2_ctrl_h264_scaling_matrix *scaling;
	const struct v4l2_ctrl_h264_sps *sps;
	const struct v4l2_ctrl_h264_pps *pps;
};

/**
 * struct hantro_h264_dec_reflists
 *
 * @p:		P reflist
 * @b0:		B0 reflist
 * @b1:		B1 reflist
 */
struct hantro_h264_dec_reflists {
	u8 p[HANTRO_H264_DPB_SIZE];
	u8 b0[HANTRO_H264_DPB_SIZE];
	u8 b1[HANTRO_H264_DPB_SIZE];
};

/**
 * struct hantro_h264_dec_hw_ctx
 *
 * @priv:	Private auxiliary buffer for hardware.
 * @dpb:	DPB
 * @reflists:	P/B0/B1 reflists
 * @ctrls:	V4L2 controls attached to a run
 * @dpb_longterm: DPB long-term
 * @dpb_valid:	  DPB valid
 */
struct hantro_h264_dec_hw_ctx {
	struct hantro_aux_buf priv;
	struct v4l2_h264_dpb_entry dpb[HANTRO_H264_DPB_SIZE];
	struct hantro_h264_dec_reflists reflists;
	struct hantro_h264_dec_ctrls ctrls;
	u32 dpb_longterm;
	u32 dpb_valid;
};

/**
 * struct hantro_hevc_dec_ctrls
 * @decode_params: Decode params
 * @scaling:	Scaling matrix
 * @sps:	SPS info
 * @pps:	PPS info
 * @hevc_hdr_skip_length: the number of data (in bits) to skip in the
 *			  slice segment header syntax after 'slice type'
 *			  token
 */
struct hantro_hevc_dec_ctrls {
	const struct v4l2_ctrl_hevc_decode_params *decode_params;
	const struct v4l2_ctrl_hevc_scaling_matrix *scaling;
	const struct v4l2_ctrl_hevc_sps *sps;
	const struct v4l2_ctrl_hevc_pps *pps;
	u32 hevc_hdr_skip_length;
};

/**
 * struct hantro_hevc_dec_hw_ctx
 * @tile_sizes:		Tile sizes buffer
 * @tile_filter:	Tile vertical filter buffer
 * @tile_sao:		Tile SAO buffer
 * @tile_bsd:		Tile BSD control buffer
 * @ref_bufs:		Internal reference buffers
 * @scaling_lists:	Scaling lists buffer
 * @ref_bufs_poc:	Internal reference buffers picture order count
 * @ref_bufs_used:	Bitfield of used reference buffers
 * @ctrls:		V4L2 controls attached to a run
 * @num_tile_cols_allocated: number of allocated tiles
 */
struct hantro_hevc_dec_hw_ctx {
	struct hantro_aux_buf tile_sizes;
	struct hantro_aux_buf tile_filter;
	struct hantro_aux_buf tile_sao;
	struct hantro_aux_buf tile_bsd;
	struct hantro_aux_buf ref_bufs[NUM_REF_PICTURES];
	struct hantro_aux_buf scaling_lists;
	int ref_bufs_poc[NUM_REF_PICTURES];
	u32 ref_bufs_used;
	struct hantro_hevc_dec_ctrls ctrls;
	unsigned int num_tile_cols_allocated;
};

/**
 * struct hantro_mpeg2_dec_hw_ctx
 *
 * @qtable:		Quantization table
 */
struct hantro_mpeg2_dec_hw_ctx {
	struct hantro_aux_buf qtable;
};

/**
 * struct hantro_vp8_dec_hw_ctx
 *
 * @segment_map:	Segment map buffer.
 * @prob_tbl:		Probability table buffer.
 */
struct hantro_vp8_dec_hw_ctx {
	struct hantro_aux_buf segment_map;
	struct hantro_aux_buf prob_tbl;
};

/**
 * struct hantro_postproc_ctx
 *
 * @dec_q:		References buffers, in decoder format.
 */
struct hantro_postproc_ctx {
	struct hantro_aux_buf dec_q[VB2_MAX_FRAME];
};

/**
 * struct hantro_codec_ops - codec mode specific operations
 *
 * @init:	If needed, can be used for initialization.
 *		Optional and called from process context.
 * @exit:	If needed, can be used to undo the .init phase.
 *		Optional and called from process context.
 * @run:	Start single {en,de)coding job. Called from atomic context
 *		to indicate that a pair of buffers is ready and the hardware
 *		should be programmed and started. Returns zero if OK, a
 *		negative value in error cases.
 * @done:	Read back processing results and additional data from hardware.
 * @reset:	Reset the hardware in case of a timeout.
 */
struct hantro_codec_ops {
	int (*init)(struct hantro_ctx *ctx);
	void (*exit)(struct hantro_ctx *ctx);
	int (*run)(struct hantro_ctx *ctx);
	void (*done)(struct hantro_ctx *ctx);
	void (*reset)(struct hantro_ctx *ctx);
};

/**
 * enum hantro_enc_fmt - source format ID for hardware registers.
 *
 * @ROCKCHIP_VPU_ENC_FMT_YUV420P: Y/CbCr 4:2:0 planar format
 * @ROCKCHIP_VPU_ENC_FMT_YUV420SP: Y/CbCr 4:2:0 semi-planar format
 * @ROCKCHIP_VPU_ENC_FMT_YUYV422: YUV 4:2:2 packed format (YUYV)
 * @ROCKCHIP_VPU_ENC_FMT_UYVY422: YUV 4:2:2 packed format (UYVY)
 */
enum hantro_enc_fmt {
	ROCKCHIP_VPU_ENC_FMT_YUV420P = 0,
	ROCKCHIP_VPU_ENC_FMT_YUV420SP = 1,
	ROCKCHIP_VPU_ENC_FMT_YUYV422 = 2,
	ROCKCHIP_VPU_ENC_FMT_UYVY422 = 3,
};

extern const struct hantro_variant imx8mq_vpu_g2_variant;
extern const struct hantro_variant imx8mq_vpu_variant;
extern const struct hantro_variant px30_vpu_variant;
extern const struct hantro_variant rk3036_vpu_variant;
extern const struct hantro_variant rk3066_vpu_variant;
extern const struct hantro_variant rk3288_vpu_variant;
extern const struct hantro_variant rk3328_vpu_variant;
extern const struct hantro_variant rk3399_vpu_variant;
extern const struct hantro_variant sama5d4_vdec_variant;

extern const struct hantro_postproc_regs hantro_g1_postproc_regs;

extern const u32 hantro_vp8_dec_mc_filter[8][6];

void hantro_watchdog(struct work_struct *work);
void hantro_run(struct hantro_ctx *ctx);
void hantro_irq_done(struct hantro_dev *vpu,
		     enum vb2_buffer_state result);
void hantro_start_prepare_run(struct hantro_ctx *ctx);
void hantro_end_prepare_run(struct hantro_ctx *ctx);

irqreturn_t hantro_g1_irq(int irq, void *dev_id);
void hantro_g1_reset(struct hantro_ctx *ctx);

int hantro_h1_jpeg_enc_run(struct hantro_ctx *ctx);
int rockchip_vpu2_jpeg_enc_run(struct hantro_ctx *ctx);
int hantro_jpeg_enc_init(struct hantro_ctx *ctx);
void hantro_jpeg_enc_exit(struct hantro_ctx *ctx);
void hantro_h1_jpeg_enc_done(struct hantro_ctx *ctx);
void rockchip_vpu2_jpeg_enc_done(struct hantro_ctx *ctx);

dma_addr_t hantro_h264_get_ref_buf(struct hantro_ctx *ctx,
				   unsigned int dpb_idx);
u16 hantro_h264_get_ref_nbr(struct hantro_ctx *ctx,
			    unsigned int dpb_idx);
int hantro_h264_dec_prepare_run(struct hantro_ctx *ctx);
int rockchip_vpu2_h264_dec_run(struct hantro_ctx *ctx);
int hantro_g1_h264_dec_run(struct hantro_ctx *ctx);
int hantro_h264_dec_init(struct hantro_ctx *ctx);
void hantro_h264_dec_exit(struct hantro_ctx *ctx);

int hantro_hevc_dec_init(struct hantro_ctx *ctx);
void hantro_hevc_dec_exit(struct hantro_ctx *ctx);
int hantro_g2_hevc_dec_run(struct hantro_ctx *ctx);
int hantro_hevc_dec_prepare_run(struct hantro_ctx *ctx);
dma_addr_t hantro_hevc_get_ref_buf(struct hantro_ctx *ctx, int poc);
void hantro_hevc_ref_remove_unused(struct hantro_ctx *ctx);
size_t hantro_hevc_chroma_offset(const struct v4l2_ctrl_hevc_sps *sps);
size_t hantro_hevc_motion_vectors_offset(const struct v4l2_ctrl_hevc_sps *sps);

static inline size_t
hantro_h264_mv_size(unsigned int width, unsigned int height)
{
	/*
	 * A decoded 8-bit 4:2:0 NV12 frame may need memory for up to
	 * 448 bytes per macroblock with additional 32 bytes on
	 * multi-core variants.
	 *
	 * The H264 decoder needs extra space on the output buffers
	 * to store motion vectors. This is needed for reference
	 * frames and only if the format is non-post-processed NV12.
	 *
	 * Memory layout is as follow:
	 *
	 * +---------------------------+
	 * | Y-plane   256 bytes x MBs |
	 * +---------------------------+
	 * | UV-plane  128 bytes x MBs |
	 * +---------------------------+
	 * | MV buffer  64 bytes x MBs |
	 * +---------------------------+
	 * | MC sync          32 bytes |
	 * +---------------------------+
	 */
	return 64 * MB_WIDTH(width) * MB_WIDTH(height) + 32;
}

int hantro_g1_mpeg2_dec_run(struct hantro_ctx *ctx);
int rockchip_vpu2_mpeg2_dec_run(struct hantro_ctx *ctx);
void hantro_mpeg2_dec_copy_qtable(u8 *qtable,
				  const struct v4l2_ctrl_mpeg2_quantisation *ctrl);
int hantro_mpeg2_dec_init(struct hantro_ctx *ctx);
void hantro_mpeg2_dec_exit(struct hantro_ctx *ctx);

int hantro_g1_vp8_dec_run(struct hantro_ctx *ctx);
int rockchip_vpu2_vp8_dec_run(struct hantro_ctx *ctx);
int hantro_vp8_dec_init(struct hantro_ctx *ctx);
void hantro_vp8_dec_exit(struct hantro_ctx *ctx);
void hantro_vp8_prob_update(struct hantro_ctx *ctx,
			    const struct v4l2_ctrl_vp8_frame *hdr);

#endif /* HANTRO_HW_H_ */
