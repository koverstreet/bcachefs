// SPDX-License-Identifier: GPL-2.0-only
/*
 *
 * Copyright (c) 2009, Microsoft Corporation.
 *
 * Authors:
 *   Haiyang Zhang <haiyangz@microsoft.com>
 *   Hank Janssen  <hjanssen@microsoft.com>
 *   K. Y. Srinivasan <kys@microsoft.com>
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/hyperv.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/prefetch.h>
#include <linux/io.h>
#include <asm/mshyperv.h>

#include "hyperv_vmbus.h"

#define VMBUS_PKT_TRAILER	8

/*
 * When we write to the ring buffer, check if the host needs to
 * be signaled. Here is the details of this protocol:
 *
 *	1. The host guarantees that while it is draining the
 *	   ring buffer, it will set the interrupt_mask to
 *	   indicate it does not need to be interrupted when
 *	   new data is placed.
 *
 *	2. The host guarantees that it will completely drain
 *	   the ring buffer before exiting the read loop. Further,
 *	   once the ring buffer is empty, it will clear the
 *	   interrupt_mask and re-check to see if new data has
 *	   arrived.
 *
 * KYS: Oct. 30, 2016:
 * It looks like Windows hosts have logic to deal with DOS attacks that
 * can be triggered if it receives interrupts when it is not expecting
 * the interrupt. The host expects interrupts only when the ring
 * transitions from empty to non-empty (or full to non full on the guest
 * to host ring).
 * So, base the signaling decision solely on the ring state until the
 * host logic is fixed.
 */

static void hv_signal_on_write(u32 old_write, struct vmbus_channel *channel)
{
	struct hv_ring_buffer_info *rbi = &channel->outbound;

	virt_mb();
	if (READ_ONCE(rbi->ring_buffer->interrupt_mask))
		return;

	/* check interrupt_mask before read_index */
	virt_rmb();
	/*
	 * This is the only case we need to signal when the
	 * ring transitions from being empty to non-empty.
	 */
	if (old_write == READ_ONCE(rbi->ring_buffer->read_index)) {
		++channel->intr_out_empty;
		vmbus_setevent(channel);
	}
}

/* Get the next write location for the specified ring buffer. */
static inline u32
hv_get_next_write_location(struct hv_ring_buffer_info *ring_info)
{
	u32 next = ring_info->ring_buffer->write_index;

	return next;
}

/* Set the next write location for the specified ring buffer. */
static inline void
hv_set_next_write_location(struct hv_ring_buffer_info *ring_info,
		     u32 next_write_location)
{
	ring_info->ring_buffer->write_index = next_write_location;
}

/* Get the size of the ring buffer. */
static inline u32
hv_get_ring_buffersize(const struct hv_ring_buffer_info *ring_info)
{
	return ring_info->ring_datasize;
}

/* Get the read and write indices as u64 of the specified ring buffer. */
static inline u64
hv_get_ring_bufferindices(struct hv_ring_buffer_info *ring_info)
{
	return (u64)ring_info->ring_buffer->write_index << 32;
}

/*
 * Helper routine to copy from source to ring buffer.
 * Assume there is enough room. Handles wrap-around in dest case only!!
 */
static u32 hv_copyto_ringbuffer(
	struct hv_ring_buffer_info	*ring_info,
	u32				start_write_offset,
	const void			*src,
	u32				srclen)
{
	void *ring_buffer = hv_get_ring_buffer(ring_info);
	u32 ring_buffer_size = hv_get_ring_buffersize(ring_info);

	memcpy(ring_buffer + start_write_offset, src, srclen);

	start_write_offset += srclen;
	if (start_write_offset >= ring_buffer_size)
		start_write_offset -= ring_buffer_size;

	return start_write_offset;
}

/*
 *
 * hv_get_ringbuffer_availbytes()
 *
 * Get number of bytes available to read and to write to
 * for the specified ring buffer
 */
static void
hv_get_ringbuffer_availbytes(const struct hv_ring_buffer_info *rbi,
			     u32 *read, u32 *write)
{
	u32 read_loc, write_loc, dsize;

	/* Capture the read/write indices before they changed */
	read_loc = READ_ONCE(rbi->ring_buffer->read_index);
	write_loc = READ_ONCE(rbi->ring_buffer->write_index);
	dsize = rbi->ring_datasize;

	*write = write_loc >= read_loc ? dsize - (write_loc - read_loc) :
		read_loc - write_loc;
	*read = dsize - *write;
}

/* Get various debug metrics for the specified ring buffer. */
int hv_ringbuffer_get_debuginfo(struct hv_ring_buffer_info *ring_info,
				struct hv_ring_buffer_debug_info *debug_info)
{
	u32 bytes_avail_towrite;
	u32 bytes_avail_toread;

	mutex_lock(&ring_info->ring_buffer_mutex);

	if (!ring_info->ring_buffer) {
		mutex_unlock(&ring_info->ring_buffer_mutex);
		return -EINVAL;
	}

	hv_get_ringbuffer_availbytes(ring_info,
				     &bytes_avail_toread,
				     &bytes_avail_towrite);
	debug_info->bytes_avail_toread = bytes_avail_toread;
	debug_info->bytes_avail_towrite = bytes_avail_towrite;
	debug_info->current_read_index = ring_info->ring_buffer->read_index;
	debug_info->current_write_index = ring_info->ring_buffer->write_index;
	debug_info->current_interrupt_mask
		= ring_info->ring_buffer->interrupt_mask;
	mutex_unlock(&ring_info->ring_buffer_mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(hv_ringbuffer_get_debuginfo);

/* Initialize a channel's ring buffer info mutex locks */
void hv_ringbuffer_pre_init(struct vmbus_channel *channel)
{
	mutex_init(&channel->inbound.ring_buffer_mutex);
	mutex_init(&channel->outbound.ring_buffer_mutex);
}

/* Initialize the ring buffer. */
int hv_ringbuffer_init(struct hv_ring_buffer_info *ring_info,
		       struct page *pages, u32 page_cnt, u32 max_pkt_size)
{
	struct page **pages_wraparound;
	unsigned long *pfns_wraparound;
	u64 pfn;
	int i;

	BUILD_BUG_ON((sizeof(struct hv_ring_buffer) != PAGE_SIZE));

	/*
	 * First page holds struct hv_ring_buffer, do wraparound mapping for
	 * the rest.
	 */
	if (hv_isolation_type_snp()) {
		pfn = page_to_pfn(pages) +
			PFN_DOWN(ms_hyperv.shared_gpa_boundary);

		pfns_wraparound = kcalloc(page_cnt * 2 - 1,
			sizeof(unsigned long), GFP_KERNEL);
		if (!pfns_wraparound)
			return -ENOMEM;

		pfns_wraparound[0] = pfn;
		for (i = 0; i < 2 * (page_cnt - 1); i++)
			pfns_wraparound[i + 1] = pfn + i % (page_cnt - 1) + 1;

		ring_info->ring_buffer = (struct hv_ring_buffer *)
			vmap_pfn(pfns_wraparound, page_cnt * 2 - 1,
				 PAGE_KERNEL);
		kfree(pfns_wraparound);

		if (!ring_info->ring_buffer)
			return -ENOMEM;

		/* Zero ring buffer after setting memory host visibility. */
		memset(ring_info->ring_buffer, 0x00, PAGE_SIZE * page_cnt);
	} else {
		pages_wraparound = kcalloc(page_cnt * 2 - 1,
					   sizeof(struct page *),
					   GFP_KERNEL);
		if (!pages_wraparound)
			return -ENOMEM;

		pages_wraparound[0] = pages;
		for (i = 0; i < 2 * (page_cnt - 1); i++)
			pages_wraparound[i + 1] =
				&pages[i % (page_cnt - 1) + 1];

		ring_info->ring_buffer = (struct hv_ring_buffer *)
			vmap(pages_wraparound, page_cnt * 2 - 1, VM_MAP,
				PAGE_KERNEL);

		kfree(pages_wraparound);
		if (!ring_info->ring_buffer)
			return -ENOMEM;
	}


	ring_info->ring_buffer->read_index =
		ring_info->ring_buffer->write_index = 0;

	/* Set the feature bit for enabling flow control. */
	ring_info->ring_buffer->feature_bits.value = 1;

	ring_info->ring_size = page_cnt << PAGE_SHIFT;
	ring_info->ring_size_div10_reciprocal =
		reciprocal_value(ring_info->ring_size / 10);
	ring_info->ring_datasize = ring_info->ring_size -
		sizeof(struct hv_ring_buffer);
	ring_info->priv_read_index = 0;

	/* Initialize buffer that holds copies of incoming packets */
	if (max_pkt_size) {
		ring_info->pkt_buffer = kzalloc(max_pkt_size, GFP_KERNEL);
		if (!ring_info->pkt_buffer)
			return -ENOMEM;
		ring_info->pkt_buffer_size = max_pkt_size;
	}

	spin_lock_init(&ring_info->ring_lock);

	return 0;
}

/* Cleanup the ring buffer. */
void hv_ringbuffer_cleanup(struct hv_ring_buffer_info *ring_info)
{
	mutex_lock(&ring_info->ring_buffer_mutex);
	vunmap(ring_info->ring_buffer);
	ring_info->ring_buffer = NULL;
	mutex_unlock(&ring_info->ring_buffer_mutex);

	kfree(ring_info->pkt_buffer);
	ring_info->pkt_buffer = NULL;
	ring_info->pkt_buffer_size = 0;
}

/* Write to the ring buffer. */
int hv_ringbuffer_write(struct vmbus_channel *channel,
			const struct kvec *kv_list, u32 kv_count,
			u64 requestid)
{
	int i;
	u32 bytes_avail_towrite;
	u32 totalbytes_towrite = sizeof(u64);
	u32 next_write_location;
	u32 old_write;
	u64 prev_indices;
	unsigned long flags;
	struct hv_ring_buffer_info *outring_info = &channel->outbound;
	struct vmpacket_descriptor *desc = kv_list[0].iov_base;
	u64 rqst_id = VMBUS_NO_RQSTOR;

	if (channel->rescind)
		return -ENODEV;

	for (i = 0; i < kv_count; i++)
		totalbytes_towrite += kv_list[i].iov_len;

	spin_lock_irqsave(&outring_info->ring_lock, flags);

	bytes_avail_towrite = hv_get_bytes_to_write(outring_info);

	/*
	 * If there is only room for the packet, assume it is full.
	 * Otherwise, the next time around, we think the ring buffer
	 * is empty since the read index == write index.
	 */
	if (bytes_avail_towrite <= totalbytes_towrite) {
		++channel->out_full_total;

		if (!channel->out_full_flag) {
			++channel->out_full_first;
			channel->out_full_flag = true;
		}

		spin_unlock_irqrestore(&outring_info->ring_lock, flags);
		return -EAGAIN;
	}

	channel->out_full_flag = false;

	/* Write to the ring buffer */
	next_write_location = hv_get_next_write_location(outring_info);

	old_write = next_write_location;

	for (i = 0; i < kv_count; i++) {
		next_write_location = hv_copyto_ringbuffer(outring_info,
						     next_write_location,
						     kv_list[i].iov_base,
						     kv_list[i].iov_len);
	}

	/*
	 * Allocate the request ID after the data has been copied into the
	 * ring buffer.  Once this request ID is allocated, the completion
	 * path could find the data and free it.
	 */

	if (desc->flags == VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED) {
		if (channel->next_request_id_callback != NULL) {
			rqst_id = channel->next_request_id_callback(channel, requestid);
			if (rqst_id == VMBUS_RQST_ERROR) {
				spin_unlock_irqrestore(&outring_info->ring_lock, flags);
				return -EAGAIN;
			}
		}
	}
	desc = hv_get_ring_buffer(outring_info) + old_write;
	desc->trans_id = (rqst_id == VMBUS_NO_RQSTOR) ? requestid : rqst_id;

	/* Set previous packet start */
	prev_indices = hv_get_ring_bufferindices(outring_info);

	next_write_location = hv_copyto_ringbuffer(outring_info,
					     next_write_location,
					     &prev_indices,
					     sizeof(u64));

	/* Issue a full memory barrier before updating the write index */
	virt_mb();

	/* Now, update the write location */
	hv_set_next_write_location(outring_info, next_write_location);


	spin_unlock_irqrestore(&outring_info->ring_lock, flags);

	hv_signal_on_write(old_write, channel);

	if (channel->rescind) {
		if (rqst_id != VMBUS_NO_RQSTOR) {
			/* Reclaim request ID to avoid leak of IDs */
			if (channel->request_addr_callback != NULL)
				channel->request_addr_callback(channel, rqst_id);
		}
		return -ENODEV;
	}

	return 0;
}

int hv_ringbuffer_read(struct vmbus_channel *channel,
		       void *buffer, u32 buflen, u32 *buffer_actual_len,
		       u64 *requestid, bool raw)
{
	struct vmpacket_descriptor *desc;
	u32 packetlen, offset;

	if (unlikely(buflen == 0))
		return -EINVAL;

	*buffer_actual_len = 0;
	*requestid = 0;

	/* Make sure there is something to read */
	desc = hv_pkt_iter_first(channel);
	if (desc == NULL) {
		/*
		 * No error is set when there is even no header, drivers are
		 * supposed to analyze buffer_actual_len.
		 */
		return 0;
	}

	offset = raw ? 0 : (desc->offset8 << 3);
	packetlen = (desc->len8 << 3) - offset;
	*buffer_actual_len = packetlen;
	*requestid = desc->trans_id;

	if (unlikely(packetlen > buflen))
		return -ENOBUFS;

	/* since ring is double mapped, only one copy is necessary */
	memcpy(buffer, (const char *)desc + offset, packetlen);

	/* Advance ring index to next packet descriptor */
	__hv_pkt_iter_next(channel, desc, true);

	/* Notify host of update */
	hv_pkt_iter_close(channel);

	return 0;
}

/*
 * Determine number of bytes available in ring buffer after
 * the current iterator (priv_read_index) location.
 *
 * This is similar to hv_get_bytes_to_read but with private
 * read index instead.
 */
static u32 hv_pkt_iter_avail(const struct hv_ring_buffer_info *rbi)
{
	u32 priv_read_loc = rbi->priv_read_index;
	u32 write_loc = READ_ONCE(rbi->ring_buffer->write_index);

	if (write_loc >= priv_read_loc)
		return write_loc - priv_read_loc;
	else
		return (rbi->ring_datasize - priv_read_loc) + write_loc;
}

/*
 * Get first vmbus packet without copying it out of the ring buffer
 */
struct vmpacket_descriptor *hv_pkt_iter_first_raw(struct vmbus_channel *channel)
{
	struct hv_ring_buffer_info *rbi = &channel->inbound;

	hv_debug_delay_test(channel, MESSAGE_DELAY);

	if (hv_pkt_iter_avail(rbi) < sizeof(struct vmpacket_descriptor))
		return NULL;

	return (struct vmpacket_descriptor *)(hv_get_ring_buffer(rbi) + rbi->priv_read_index);
}
EXPORT_SYMBOL_GPL(hv_pkt_iter_first_raw);

/*
 * Get first vmbus packet from ring buffer after read_index
 *
 * If ring buffer is empty, returns NULL and no other action needed.
 */
struct vmpacket_descriptor *hv_pkt_iter_first(struct vmbus_channel *channel)
{
	struct hv_ring_buffer_info *rbi = &channel->inbound;
	struct vmpacket_descriptor *desc, *desc_copy;
	u32 bytes_avail, pkt_len, pkt_offset;

	desc = hv_pkt_iter_first_raw(channel);
	if (!desc)
		return NULL;

	bytes_avail = min(rbi->pkt_buffer_size, hv_pkt_iter_avail(rbi));

	/*
	 * Ensure the compiler does not use references to incoming Hyper-V values (which
	 * could change at any moment) when reading local variables later in the code
	 */
	pkt_len = READ_ONCE(desc->len8) << 3;
	pkt_offset = READ_ONCE(desc->offset8) << 3;

	/*
	 * If pkt_len is invalid, set it to the smaller of hv_pkt_iter_avail() and
	 * rbi->pkt_buffer_size
	 */
	if (pkt_len < sizeof(struct vmpacket_descriptor) || pkt_len > bytes_avail)
		pkt_len = bytes_avail;

	/*
	 * If pkt_offset is invalid, arbitrarily set it to
	 * the size of vmpacket_descriptor
	 */
	if (pkt_offset < sizeof(struct vmpacket_descriptor) || pkt_offset > pkt_len)
		pkt_offset = sizeof(struct vmpacket_descriptor);

	/* Copy the Hyper-V packet out of the ring buffer */
	desc_copy = (struct vmpacket_descriptor *)rbi->pkt_buffer;
	memcpy(desc_copy, desc, pkt_len);

	/*
	 * Hyper-V could still change len8 and offset8 after the earlier read.
	 * Ensure that desc_copy has legal values for len8 and offset8 that
	 * are consistent with the copy we just made
	 */
	desc_copy->len8 = pkt_len >> 3;
	desc_copy->offset8 = pkt_offset >> 3;

	return desc_copy;
}
EXPORT_SYMBOL_GPL(hv_pkt_iter_first);

/*
 * Get next vmbus packet from ring buffer.
 *
 * Advances the current location (priv_read_index) and checks for more
 * data. If the end of the ring buffer is reached, then return NULL.
 */
struct vmpacket_descriptor *
__hv_pkt_iter_next(struct vmbus_channel *channel,
		   const struct vmpacket_descriptor *desc,
		   bool copy)
{
	struct hv_ring_buffer_info *rbi = &channel->inbound;
	u32 packetlen = desc->len8 << 3;
	u32 dsize = rbi->ring_datasize;

	hv_debug_delay_test(channel, MESSAGE_DELAY);
	/* bump offset to next potential packet */
	rbi->priv_read_index += packetlen + VMBUS_PKT_TRAILER;
	if (rbi->priv_read_index >= dsize)
		rbi->priv_read_index -= dsize;

	/* more data? */
	return copy ? hv_pkt_iter_first(channel) : hv_pkt_iter_first_raw(channel);
}
EXPORT_SYMBOL_GPL(__hv_pkt_iter_next);

/* How many bytes were read in this iterator cycle */
static u32 hv_pkt_iter_bytes_read(const struct hv_ring_buffer_info *rbi,
					u32 start_read_index)
{
	if (rbi->priv_read_index >= start_read_index)
		return rbi->priv_read_index - start_read_index;
	else
		return rbi->ring_datasize - start_read_index +
			rbi->priv_read_index;
}

/*
 * Update host ring buffer after iterating over packets. If the host has
 * stopped queuing new entries because it found the ring buffer full, and
 * sufficient space is being freed up, signal the host. But be careful to
 * only signal the host when necessary, both for performance reasons and
 * because Hyper-V protects itself by throttling guests that signal
 * inappropriately.
 *
 * Determining when to signal is tricky. There are three key data inputs
 * that must be handled in this order to avoid race conditions:
 *
 * 1. Update the read_index
 * 2. Read the pending_send_sz
 * 3. Read the current write_index
 *
 * The interrupt_mask is not used to determine when to signal. The
 * interrupt_mask is used only on the guest->host ring buffer when
 * sending requests to the host. The host does not use it on the host->
 * guest ring buffer to indicate whether it should be signaled.
 */
void hv_pkt_iter_close(struct vmbus_channel *channel)
{
	struct hv_ring_buffer_info *rbi = &channel->inbound;
	u32 curr_write_sz, pending_sz, bytes_read, start_read_index;

	/*
	 * Make sure all reads are done before we update the read index since
	 * the writer may start writing to the read area once the read index
	 * is updated.
	 */
	virt_rmb();
	start_read_index = rbi->ring_buffer->read_index;
	rbi->ring_buffer->read_index = rbi->priv_read_index;

	/*
	 * Older versions of Hyper-V (before WS2102 and Win8) do not
	 * implement pending_send_sz and simply poll if the host->guest
	 * ring buffer is full.  No signaling is needed or expected.
	 */
	if (!rbi->ring_buffer->feature_bits.feat_pending_send_sz)
		return;

	/*
	 * Issue a full memory barrier before making the signaling decision.
	 * If reading pending_send_sz were to be reordered and happen
	 * before we commit the new read_index, a race could occur.  If the
	 * host were to set the pending_send_sz after we have sampled
	 * pending_send_sz, and the ring buffer blocks before we commit the
	 * read index, we could miss sending the interrupt. Issue a full
	 * memory barrier to address this.
	 */
	virt_mb();

	/*
	 * If the pending_send_sz is zero, then the ring buffer is not
	 * blocked and there is no need to signal.  This is far by the
	 * most common case, so exit quickly for best performance.
	 */
	pending_sz = READ_ONCE(rbi->ring_buffer->pending_send_sz);
	if (!pending_sz)
		return;

	/*
	 * Ensure the read of write_index in hv_get_bytes_to_write()
	 * happens after the read of pending_send_sz.
	 */
	virt_rmb();
	curr_write_sz = hv_get_bytes_to_write(rbi);
	bytes_read = hv_pkt_iter_bytes_read(rbi, start_read_index);

	/*
	 * We want to signal the host only if we're transitioning
	 * from a "not enough free space" state to a "enough free
	 * space" state.  For example, it's possible that this function
	 * could run and free up enough space to signal the host, and then
	 * run again and free up additional space before the host has a
	 * chance to clear the pending_send_sz.  The 2nd invocation would
	 * be a null transition from "enough free space" to "enough free
	 * space", which doesn't warrant a signal.
	 *
	 * Exactly filling the ring buffer is treated as "not enough
	 * space". The ring buffer always must have at least one byte
	 * empty so the empty and full conditions are distinguishable.
	 * hv_get_bytes_to_write() doesn't fully tell the truth in
	 * this regard.
	 *
	 * So first check if we were in the "enough free space" state
	 * before we began the iteration. If so, the host was not
	 * blocked, and there's no need to signal.
	 */
	if (curr_write_sz - bytes_read > pending_sz)
		return;

	/*
	 * Similarly, if the new state is "not enough space", then
	 * there's no need to signal.
	 */
	if (curr_write_sz <= pending_sz)
		return;

	++channel->intr_in_full;
	vmbus_setevent(channel);
}
EXPORT_SYMBOL_GPL(hv_pkt_iter_close);
