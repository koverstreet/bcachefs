// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2018 Intel Corporation. */

#include <linux/bpf_trace.h>
#include <net/xdp_sock_drv.h>
#include <net/xdp.h>

#include "i40e.h"
#include "i40e_txrx_common.h"
#include "i40e_xsk.h"

int i40e_alloc_rx_bi_zc(struct i40e_ring *rx_ring)
{
	unsigned long sz = sizeof(*rx_ring->rx_bi_zc) * rx_ring->count;

	rx_ring->rx_bi_zc = kzalloc(sz, GFP_KERNEL);
	return rx_ring->rx_bi_zc ? 0 : -ENOMEM;
}

void i40e_clear_rx_bi_zc(struct i40e_ring *rx_ring)
{
	memset(rx_ring->rx_bi_zc, 0,
	       sizeof(*rx_ring->rx_bi_zc) * rx_ring->count);
}

static struct xdp_buff **i40e_rx_bi(struct i40e_ring *rx_ring, u32 idx)
{
	return &rx_ring->rx_bi_zc[idx];
}

/**
 * i40e_xsk_umem_enable - Enable/associate a UMEM to a certain ring/qid
 * @vsi: Current VSI
 * @umem: UMEM
 * @qid: Rx ring to associate UMEM to
 *
 * Returns 0 on success, <0 on failure
 **/
static int i40e_xsk_umem_enable(struct i40e_vsi *vsi, struct xdp_umem *umem,
				u16 qid)
{
	struct net_device *netdev = vsi->netdev;
	bool if_running;
	int err;

	if (vsi->type != I40E_VSI_MAIN)
		return -EINVAL;

	if (qid >= vsi->num_queue_pairs)
		return -EINVAL;

	if (qid >= netdev->real_num_rx_queues ||
	    qid >= netdev->real_num_tx_queues)
		return -EINVAL;

	err = xsk_buff_dma_map(umem, &vsi->back->pdev->dev, I40E_RX_DMA_ATTR);
	if (err)
		return err;

	set_bit(qid, vsi->af_xdp_zc_qps);

	if_running = netif_running(vsi->netdev) && i40e_enabled_xdp_vsi(vsi);

	if (if_running) {
		err = i40e_queue_pair_disable(vsi, qid);
		if (err)
			return err;

		err = i40e_queue_pair_enable(vsi, qid);
		if (err)
			return err;

		/* Kick start the NAPI context so that receiving will start */
		err = i40e_xsk_wakeup(vsi->netdev, qid, XDP_WAKEUP_RX);
		if (err)
			return err;
	}

	return 0;
}

/**
 * i40e_xsk_umem_disable - Disassociate a UMEM from a certain ring/qid
 * @vsi: Current VSI
 * @qid: Rx ring to associate UMEM to
 *
 * Returns 0 on success, <0 on failure
 **/
static int i40e_xsk_umem_disable(struct i40e_vsi *vsi, u16 qid)
{
	struct net_device *netdev = vsi->netdev;
	struct xdp_umem *umem;
	bool if_running;
	int err;

	umem = xdp_get_umem_from_qid(netdev, qid);
	if (!umem)
		return -EINVAL;

	if_running = netif_running(vsi->netdev) && i40e_enabled_xdp_vsi(vsi);

	if (if_running) {
		err = i40e_queue_pair_disable(vsi, qid);
		if (err)
			return err;
	}

	clear_bit(qid, vsi->af_xdp_zc_qps);
	xsk_buff_dma_unmap(umem, I40E_RX_DMA_ATTR);

	if (if_running) {
		err = i40e_queue_pair_enable(vsi, qid);
		if (err)
			return err;
	}

	return 0;
}

/**
 * i40e_xsk_umem_setup - Enable/disassociate a UMEM to/from a ring/qid
 * @vsi: Current VSI
 * @umem: UMEM to enable/associate to a ring, or NULL to disable
 * @qid: Rx ring to (dis)associate UMEM (from)to
 *
 * This function enables or disables a UMEM to a certain ring.
 *
 * Returns 0 on success, <0 on failure
 **/
int i40e_xsk_umem_setup(struct i40e_vsi *vsi, struct xdp_umem *umem,
			u16 qid)
{
	return umem ? i40e_xsk_umem_enable(vsi, umem, qid) :
		i40e_xsk_umem_disable(vsi, qid);
}

/**
 * i40e_run_xdp_zc - Executes an XDP program on an xdp_buff
 * @rx_ring: Rx ring
 * @xdp: xdp_buff used as input to the XDP program
 *
 * Returns any of I40E_XDP_{PASS, CONSUMED, TX, REDIR}
 **/
static int i40e_run_xdp_zc(struct i40e_ring *rx_ring, struct xdp_buff *xdp)
{
	int err, result = I40E_XDP_PASS;
	struct i40e_ring *xdp_ring;
	struct bpf_prog *xdp_prog;
	u32 act;

	rcu_read_lock();
	/* NB! xdp_prog will always be !NULL, due to the fact that
	 * this path is enabled by setting an XDP program.
	 */
	xdp_prog = READ_ONCE(rx_ring->xdp_prog);
	act = bpf_prog_run_xdp(xdp_prog, xdp);

	switch (act) {
	case XDP_PASS:
		break;
	case XDP_TX:
		xdp_ring = rx_ring->vsi->xdp_rings[rx_ring->queue_index];
		result = i40e_xmit_xdp_tx_ring(xdp, xdp_ring);
		break;
	case XDP_REDIRECT:
		err = xdp_do_redirect(rx_ring->netdev, xdp, xdp_prog);
		result = !err ? I40E_XDP_REDIR : I40E_XDP_CONSUMED;
		break;
	default:
		bpf_warn_invalid_xdp_action(act);
		/* fall through */
	case XDP_ABORTED:
		trace_xdp_exception(rx_ring->netdev, xdp_prog, act);
		/* fallthrough -- handle aborts by dropping packet */
	case XDP_DROP:
		result = I40E_XDP_CONSUMED;
		break;
	}
	rcu_read_unlock();
	return result;
}

bool i40e_alloc_rx_buffers_zc(struct i40e_ring *rx_ring, u16 count)
{
	u16 ntu = rx_ring->next_to_use;
	union i40e_rx_desc *rx_desc;
	struct xdp_buff **bi, *xdp;
	dma_addr_t dma;
	bool ok = true;

	rx_desc = I40E_RX_DESC(rx_ring, ntu);
	bi = i40e_rx_bi(rx_ring, ntu);
	do {
		xdp = xsk_buff_alloc(rx_ring->xsk_umem);
		if (!xdp) {
			ok = false;
			goto no_buffers;
		}
		*bi = xdp;
		dma = xsk_buff_xdp_get_dma(xdp);
		rx_desc->read.pkt_addr = cpu_to_le64(dma);
		rx_desc->read.hdr_addr = 0;

		rx_desc++;
		bi++;
		ntu++;

		if (unlikely(ntu == rx_ring->count)) {
			rx_desc = I40E_RX_DESC(rx_ring, 0);
			bi = i40e_rx_bi(rx_ring, 0);
			ntu = 0;
		}

		count--;
	} while (count);

no_buffers:
	if (rx_ring->next_to_use != ntu)
		i40e_release_rx_desc(rx_ring, ntu);

	return ok;
}

/**
 * i40e_construct_skb_zc - Create skbuff from zero-copy Rx buffer
 * @rx_ring: Rx ring
 * @xdp: xdp_buff
 *
 * This functions allocates a new skb from a zero-copy Rx buffer.
 *
 * Returns the skb, or NULL on failure.
 **/
static struct sk_buff *i40e_construct_skb_zc(struct i40e_ring *rx_ring,
					     struct xdp_buff *xdp)
{
	unsigned int metasize = xdp->data - xdp->data_meta;
	unsigned int datasize = xdp->data_end - xdp->data;
	struct sk_buff *skb;

	/* allocate a skb to store the frags */
	skb = __napi_alloc_skb(&rx_ring->q_vector->napi,
			       xdp->data_end - xdp->data_hard_start,
			       GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!skb))
		return NULL;

	skb_reserve(skb, xdp->data - xdp->data_hard_start);
	memcpy(__skb_put(skb, datasize), xdp->data, datasize);
	if (metasize)
		skb_metadata_set(skb, metasize);

	xsk_buff_free(xdp);
	return skb;
}

/**
 * i40e_clean_rx_irq_zc - Consumes Rx packets from the hardware ring
 * @rx_ring: Rx ring
 * @budget: NAPI budget
 *
 * Returns amount of work completed
 **/
int i40e_clean_rx_irq_zc(struct i40e_ring *rx_ring, int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;
	u16 cleaned_count = I40E_DESC_UNUSED(rx_ring);
	unsigned int xdp_res, xdp_xmit = 0;
	bool failure = false;
	struct sk_buff *skb;

	while (likely(total_rx_packets < (unsigned int)budget)) {
		union i40e_rx_desc *rx_desc;
		struct xdp_buff **bi;
		unsigned int size;
		u64 qword;

		if (cleaned_count >= I40E_RX_BUFFER_WRITE) {
			failure = failure ||
				  !i40e_alloc_rx_buffers_zc(rx_ring,
							    cleaned_count);
			cleaned_count = 0;
		}

		rx_desc = I40E_RX_DESC(rx_ring, rx_ring->next_to_clean);
		qword = le64_to_cpu(rx_desc->wb.qword1.status_error_len);

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we have
		 * verified the descriptor has been written back.
		 */
		dma_rmb();

		if (i40e_rx_is_programming_status(qword)) {
			i40e_clean_programming_status(rx_ring,
						      rx_desc->raw.qword[0],
						      qword);
			bi = i40e_rx_bi(rx_ring, rx_ring->next_to_clean);
			xsk_buff_free(*bi);
			*bi = NULL;
			cleaned_count++;
			i40e_inc_ntc(rx_ring);
			continue;
		}

		bi = i40e_rx_bi(rx_ring, rx_ring->next_to_clean);
		size = (qword & I40E_RXD_QW1_LENGTH_PBUF_MASK) >>
		       I40E_RXD_QW1_LENGTH_PBUF_SHIFT;
		if (!size)
			break;

		bi = i40e_rx_bi(rx_ring, rx_ring->next_to_clean);
		(*bi)->data_end = (*bi)->data + size;
		xsk_buff_dma_sync_for_cpu(*bi);

		xdp_res = i40e_run_xdp_zc(rx_ring, *bi);
		if (xdp_res) {
			if (xdp_res & (I40E_XDP_TX | I40E_XDP_REDIR))
				xdp_xmit |= xdp_res;
			else
				xsk_buff_free(*bi);

			*bi = NULL;
			total_rx_bytes += size;
			total_rx_packets++;

			cleaned_count++;
			i40e_inc_ntc(rx_ring);
			continue;
		}

		/* XDP_PASS path */

		/* NB! We are not checking for errors using
		 * i40e_test_staterr with
		 * BIT(I40E_RXD_QW1_ERROR_SHIFT). This is due to that
		 * SBP is *not* set in PRT_SBPVSI (default not set).
		 */
		skb = i40e_construct_skb_zc(rx_ring, *bi);
		*bi = NULL;
		if (!skb) {
			rx_ring->rx_stats.alloc_buff_failed++;
			break;
		}

		cleaned_count++;
		i40e_inc_ntc(rx_ring);

		if (eth_skb_pad(skb))
			continue;

		total_rx_bytes += skb->len;
		total_rx_packets++;

		i40e_process_skb_fields(rx_ring, rx_desc, skb);
		napi_gro_receive(&rx_ring->q_vector->napi, skb);
	}

	i40e_finalize_xdp_rx(rx_ring, xdp_xmit);
	i40e_update_rx_stats(rx_ring, total_rx_bytes, total_rx_packets);

	if (xsk_umem_uses_need_wakeup(rx_ring->xsk_umem)) {
		if (failure || rx_ring->next_to_clean == rx_ring->next_to_use)
			xsk_set_rx_need_wakeup(rx_ring->xsk_umem);
		else
			xsk_clear_rx_need_wakeup(rx_ring->xsk_umem);

		return (int)total_rx_packets;
	}
	return failure ? budget : (int)total_rx_packets;
}

/**
 * i40e_xmit_zc - Performs zero-copy Tx AF_XDP
 * @xdp_ring: XDP Tx ring
 * @budget: NAPI budget
 *
 * Returns true if the work is finished.
 **/
static bool i40e_xmit_zc(struct i40e_ring *xdp_ring, unsigned int budget)
{
	struct i40e_tx_desc *tx_desc = NULL;
	struct i40e_tx_buffer *tx_bi;
	bool work_done = true;
	struct xdp_desc desc;
	dma_addr_t dma;

	while (budget-- > 0) {
		if (!unlikely(I40E_DESC_UNUSED(xdp_ring))) {
			xdp_ring->tx_stats.tx_busy++;
			work_done = false;
			break;
		}

		if (!xsk_umem_consume_tx(xdp_ring->xsk_umem, &desc))
			break;

		dma = xsk_buff_raw_get_dma(xdp_ring->xsk_umem, desc.addr);
		xsk_buff_raw_dma_sync_for_device(xdp_ring->xsk_umem, dma,
						 desc.len);

		tx_bi = &xdp_ring->tx_bi[xdp_ring->next_to_use];
		tx_bi->bytecount = desc.len;

		tx_desc = I40E_TX_DESC(xdp_ring, xdp_ring->next_to_use);
		tx_desc->buffer_addr = cpu_to_le64(dma);
		tx_desc->cmd_type_offset_bsz =
			build_ctob(I40E_TX_DESC_CMD_ICRC
				   | I40E_TX_DESC_CMD_EOP,
				   0, desc.len, 0);

		xdp_ring->next_to_use++;
		if (xdp_ring->next_to_use == xdp_ring->count)
			xdp_ring->next_to_use = 0;
	}

	if (tx_desc) {
		/* Request an interrupt for the last frame and bump tail ptr. */
		tx_desc->cmd_type_offset_bsz |= (I40E_TX_DESC_CMD_RS <<
						 I40E_TXD_QW1_CMD_SHIFT);
		i40e_xdp_ring_update_tail(xdp_ring);

		xsk_umem_consume_tx_done(xdp_ring->xsk_umem);
	}

	return !!budget && work_done;
}

/**
 * i40e_clean_xdp_tx_buffer - Frees and unmaps an XDP Tx entry
 * @tx_ring: XDP Tx ring
 * @tx_bi: Tx buffer info to clean
 **/
static void i40e_clean_xdp_tx_buffer(struct i40e_ring *tx_ring,
				     struct i40e_tx_buffer *tx_bi)
{
	xdp_return_frame(tx_bi->xdpf);
	dma_unmap_single(tx_ring->dev,
			 dma_unmap_addr(tx_bi, dma),
			 dma_unmap_len(tx_bi, len), DMA_TO_DEVICE);
	dma_unmap_len_set(tx_bi, len, 0);
}

/**
 * i40e_clean_xdp_tx_irq - Completes AF_XDP entries, and cleans XDP entries
 * @tx_ring: XDP Tx ring
 * @tx_bi: Tx buffer info to clean
 *
 * Returns true if cleanup/tranmission is done.
 **/
bool i40e_clean_xdp_tx_irq(struct i40e_vsi *vsi,
			   struct i40e_ring *tx_ring, int napi_budget)
{
	unsigned int ntc, total_bytes = 0, budget = vsi->work_limit;
	u32 i, completed_frames, frames_ready, xsk_frames = 0;
	struct xdp_umem *umem = tx_ring->xsk_umem;
	u32 head_idx = i40e_get_head(tx_ring);
	bool work_done = true, xmit_done;
	struct i40e_tx_buffer *tx_bi;

	if (head_idx < tx_ring->next_to_clean)
		head_idx += tx_ring->count;
	frames_ready = head_idx - tx_ring->next_to_clean;

	if (frames_ready == 0) {
		goto out_xmit;
	} else if (frames_ready > budget) {
		completed_frames = budget;
		work_done = false;
	} else {
		completed_frames = frames_ready;
	}

	ntc = tx_ring->next_to_clean;

	for (i = 0; i < completed_frames; i++) {
		tx_bi = &tx_ring->tx_bi[ntc];

		if (tx_bi->xdpf)
			i40e_clean_xdp_tx_buffer(tx_ring, tx_bi);
		else
			xsk_frames++;

		tx_bi->xdpf = NULL;
		total_bytes += tx_bi->bytecount;

		if (++ntc >= tx_ring->count)
			ntc = 0;
	}

	tx_ring->next_to_clean += completed_frames;
	if (unlikely(tx_ring->next_to_clean >= tx_ring->count))
		tx_ring->next_to_clean -= tx_ring->count;

	if (xsk_frames)
		xsk_umem_complete_tx(umem, xsk_frames);

	i40e_arm_wb(tx_ring, vsi, budget);
	i40e_update_tx_stats(tx_ring, completed_frames, total_bytes);

out_xmit:
	if (xsk_umem_uses_need_wakeup(tx_ring->xsk_umem))
		xsk_set_tx_need_wakeup(tx_ring->xsk_umem);

	xmit_done = i40e_xmit_zc(tx_ring, budget);

	return work_done && xmit_done;
}

/**
 * i40e_xsk_wakeup - Implements the ndo_xsk_wakeup
 * @dev: the netdevice
 * @queue_id: queue id to wake up
 * @flags: ignored in our case since we have Rx and Tx in the same NAPI.
 *
 * Returns <0 for errors, 0 otherwise.
 **/
int i40e_xsk_wakeup(struct net_device *dev, u32 queue_id, u32 flags)
{
	struct i40e_netdev_priv *np = netdev_priv(dev);
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_pf *pf = vsi->back;
	struct i40e_ring *ring;

	if (test_bit(__I40E_CONFIG_BUSY, pf->state))
		return -EAGAIN;

	if (test_bit(__I40E_VSI_DOWN, vsi->state))
		return -ENETDOWN;

	if (!i40e_enabled_xdp_vsi(vsi))
		return -ENXIO;

	if (queue_id >= vsi->num_queue_pairs)
		return -ENXIO;

	if (!vsi->xdp_rings[queue_id]->xsk_umem)
		return -ENXIO;

	ring = vsi->xdp_rings[queue_id];

	/* The idea here is that if NAPI is running, mark a miss, so
	 * it will run again. If not, trigger an interrupt and
	 * schedule the NAPI from interrupt context. If NAPI would be
	 * scheduled here, the interrupt affinity would not be
	 * honored.
	 */
	if (!napi_if_scheduled_mark_missed(&ring->q_vector->napi))
		i40e_force_wb(vsi, ring->q_vector);

	return 0;
}

void i40e_xsk_clean_rx_ring(struct i40e_ring *rx_ring)
{
	u16 i;

	for (i = 0; i < rx_ring->count; i++) {
		struct xdp_buff *rx_bi = *i40e_rx_bi(rx_ring, i);

		if (!rx_bi)
			continue;

		xsk_buff_free(rx_bi);
		rx_bi = NULL;
	}
}

/**
 * i40e_xsk_clean_xdp_ring - Clean the XDP Tx ring on shutdown
 * @xdp_ring: XDP Tx ring
 **/
void i40e_xsk_clean_tx_ring(struct i40e_ring *tx_ring)
{
	u16 ntc = tx_ring->next_to_clean, ntu = tx_ring->next_to_use;
	struct xdp_umem *umem = tx_ring->xsk_umem;
	struct i40e_tx_buffer *tx_bi;
	u32 xsk_frames = 0;

	while (ntc != ntu) {
		tx_bi = &tx_ring->tx_bi[ntc];

		if (tx_bi->xdpf)
			i40e_clean_xdp_tx_buffer(tx_ring, tx_bi);
		else
			xsk_frames++;

		tx_bi->xdpf = NULL;

		ntc++;
		if (ntc >= tx_ring->count)
			ntc = 0;
	}

	if (xsk_frames)
		xsk_umem_complete_tx(umem, xsk_frames);
}

/**
 * i40e_xsk_any_rx_ring_enabled - Checks if Rx rings have AF_XDP UMEM attached
 * @vsi: vsi
 *
 * Returns true if any of the Rx rings has an AF_XDP UMEM attached
 **/
bool i40e_xsk_any_rx_ring_enabled(struct i40e_vsi *vsi)
{
	struct net_device *netdev = vsi->netdev;
	int i;

	for (i = 0; i < vsi->num_queue_pairs; i++) {
		if (xdp_get_umem_from_qid(netdev, i))
			return true;
	}

	return false;
}
