/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * V4L2 JPEG helpers header
 *
 * Copyright (C) 2019 Pengutronix, Philipp Zabel <kernel@pengutronix.de>
 *
 * For reference, see JPEG ITU-T.81 (ISO/IEC 10918-1)
 */

#ifndef _V4L2_JPEG_H
#define _V4L2_JPEG_H

#include <linux/v4l2-controls.h>

#define V4L2_JPEG_MAX_COMPONENTS	4
#define V4L2_JPEG_MAX_TABLES		4

/**
 * struct v4l2_jpeg_reference - reference into the JPEG buffer
 * @start: pointer to the start of the referenced segment or table
 * @length: size of the referenced segment or table
 *
 * Wnen referencing marker segments, start points right after the marker code,
 * and length is the size of the segment parameters, excluding the marker code.
 */
struct v4l2_jpeg_reference {
	u8 *start;
	size_t length;
};

/* B.2.2 Frame header syntax */

/**
 * struct v4l2_jpeg_frame_component_spec - frame component-specification
 * @component_identifier: C[i]
 * @horizontal_sampling_factor: H[i]
 * @vertical_sampling_factor: V[i]
 * @quantization_table_selector: quantization table destination selector Tq[i]
 */
struct v4l2_jpeg_frame_component_spec {
	u8 component_identifier;
	u8 horizontal_sampling_factor;
	u8 vertical_sampling_factor;
	u8 quantization_table_selector;
};

/**
 * struct v4l2_jpeg_frame_header - JPEG frame header
 * @height: Y
 * @width: X
 * @precision: P
 * @num_components: Nf
 * @component: component-specification, see v4l2_jpeg_frame_component_spec
 * @subsampling: decoded subsampling from component-specification
 */
struct v4l2_jpeg_frame_header {
	u16 height;
	u16 width;
	u8 precision;
	u8 num_components;
	struct v4l2_jpeg_frame_component_spec component[V4L2_JPEG_MAX_COMPONENTS];
	enum v4l2_jpeg_chroma_subsampling subsampling;
};

/* B.2.3 Scan header syntax */

/**
 * struct v4l2_jpeg_scan_component_spec - scan component-specification
 * @component_selector: Cs[j]
 * @dc_entropy_coding_table_selector: Td[j]
 * @ac_entropy_coding_table_selector: Ta[j]
 */
struct v4l2_jpeg_scan_component_spec {
	u8 component_selector;
	u8 dc_entropy_coding_table_selector;
	u8 ac_entropy_coding_table_selector;
};

/**
 * struct v4l2_jpeg_scan_header - JPEG scan header
 * @num_components: Ns
 * @component: component-specification, see v4l2_jpeg_scan_component_spec
 */
struct v4l2_jpeg_scan_header {
	u8 num_components;				/* Ns */
	struct v4l2_jpeg_scan_component_spec component[V4L2_JPEG_MAX_COMPONENTS];
	/* Ss, Se, Ah, and Al are not used by any driver */
};

/**
 * struct v4l2_jpeg_header - parsed JPEG header
 * @sof: pointer to frame header and size
 * @sos: pointer to scan header and size
 * @dht: pointers to huffman tables and sizes
 * @dqt: pointers to quantization tables and sizes
 * @frame: parsed frame header
 * @scan: pointer to parsed scan header, optional
 * @quantization_tables: references to four quantization tables, optional
 * @huffman_tables: references to four Huffman tables in DC0, DC1, AC0, AC1
 *                  order, optional
 * @restart_interval: number of MCU per restart interval, Ri
 * @ecs_offset: buffer offset in bytes to the entropy coded segment
 *
 * When this structure is passed to v4l2_jpeg_parse_header, the optional scan,
 * quantization_tables, and huffman_tables pointers must be initialized to NULL
 * or point at valid memory.
 */
struct v4l2_jpeg_header {
	struct v4l2_jpeg_reference sof;
	struct v4l2_jpeg_reference sos;
	unsigned int num_dht;
	struct v4l2_jpeg_reference dht[V4L2_JPEG_MAX_TABLES];
	unsigned int num_dqt;
	struct v4l2_jpeg_reference dqt[V4L2_JPEG_MAX_TABLES];

	struct v4l2_jpeg_frame_header frame;
	struct v4l2_jpeg_scan_header *scan;
	struct v4l2_jpeg_reference *quantization_tables;
	struct v4l2_jpeg_reference *huffman_tables;
	u16 restart_interval;
	size_t ecs_offset;
};

int v4l2_jpeg_parse_header(void *buf, size_t len, struct v4l2_jpeg_header *out);

int v4l2_jpeg_parse_frame_header(void *buf, size_t len,
				 struct v4l2_jpeg_frame_header *frame_header);
int v4l2_jpeg_parse_scan_header(void *buf, size_t len,
				struct v4l2_jpeg_scan_header *scan_header);
int v4l2_jpeg_parse_quantization_tables(void *buf, size_t len, u8 precision,
					struct v4l2_jpeg_reference *q_tables);
int v4l2_jpeg_parse_huffman_tables(void *buf, size_t len,
				   struct v4l2_jpeg_reference *huffman_tables);

#endif
