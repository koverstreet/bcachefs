// SPDX-License-Identifier: GPL-2.0+
/*
 * u_audio.c -- interface to USB gadget "ALSA sound card" utilities
 *
 * Copyright (C) 2016
 * Author: Ruslan Bilovol <ruslan.bilovol@gmail.com>
 *
 * Sound card implementation was cut-and-pasted with changes
 * from f_uac2.c and has:
 *    Copyright (C) 2011
 *    Yadwinder Singh (yadi.brar01@gmail.com)
 *    Jaswinder Singh (jaswinder.singh@linaro.org)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/control.h>
#include <sound/tlv.h>
#include <linux/usb/audio.h>

#include "u_audio.h"

#define BUFF_SIZE_MAX	(PAGE_SIZE * 16)
#define PRD_SIZE_MAX	PAGE_SIZE
#define MIN_PERIODS	4

enum {
	UAC_FBACK_CTRL,
	UAC_P_PITCH_CTRL,
	UAC_MUTE_CTRL,
	UAC_VOLUME_CTRL,
};

/* Runtime data params for one stream */
struct uac_rtd_params {
	struct snd_uac_chip *uac; /* parent chip */
	bool ep_enabled; /* if the ep is enabled */

	struct snd_pcm_substream *ss;

	/* Ring buffer */
	ssize_t hw_ptr;

	void *rbuf;

	unsigned int pitch;	/* Stream pitch ratio to 1000000 */
	unsigned int max_psize;	/* MaxPacketSize of endpoint */

	struct usb_request **reqs;

	struct usb_request *req_fback; /* Feedback endpoint request */
	bool fb_ep_enabled; /* if the ep is enabled */

  /* Volume/Mute controls and their state */
  int fu_id; /* Feature Unit ID */
  struct snd_kcontrol *snd_kctl_volume;
  struct snd_kcontrol *snd_kctl_mute;
  s16 volume_min, volume_max, volume_res;
  s16 volume;
  int mute;

  spinlock_t lock; /* lock for control transfers */

};

struct snd_uac_chip {
	struct g_audio *audio_dev;

	struct uac_rtd_params p_prm;
	struct uac_rtd_params c_prm;

	struct snd_card *card;
	struct snd_pcm *pcm;

	/* pre-calculated values for playback iso completion */
	unsigned long long p_residue_mil;
	unsigned int p_interval;
	unsigned int p_framesize;
};

static const struct snd_pcm_hardware uac_pcm_hardware = {
	.info = SNDRV_PCM_INFO_INTERLEAVED | SNDRV_PCM_INFO_BLOCK_TRANSFER
		 | SNDRV_PCM_INFO_MMAP | SNDRV_PCM_INFO_MMAP_VALID
		 | SNDRV_PCM_INFO_PAUSE | SNDRV_PCM_INFO_RESUME,
	.rates = SNDRV_PCM_RATE_CONTINUOUS,
	.periods_max = BUFF_SIZE_MAX / PRD_SIZE_MAX,
	.buffer_bytes_max = BUFF_SIZE_MAX,
	.period_bytes_max = PRD_SIZE_MAX,
	.periods_min = MIN_PERIODS,
};

static void u_audio_set_fback_frequency(enum usb_device_speed speed,
					struct usb_ep *out_ep,
					unsigned long long freq,
					unsigned int pitch,
					void *buf)
{
	u32 ff = 0;
	const struct usb_endpoint_descriptor *ep_desc;

	/*
	 * Because the pitch base is 1000000, the final divider here
	 * will be 1000 * 1000000 = 1953125 << 9
	 *
	 * Instead of dealing with big numbers lets fold this 9 left shift
	 */

	if (speed == USB_SPEED_FULL) {
		/*
		 * Full-speed feedback endpoints report frequency
		 * in samples/frame
		 * Format is encoded in Q10.10 left-justified in the 24 bits,
		 * so that it has a Q10.14 format.
		 *
		 * ff = (freq << 14) / 1000
		 */
		freq <<= 5;
	} else {
		/*
		 * High-speed feedback endpoints report frequency
		 * in samples/microframe.
		 * Format is encoded in Q12.13 fitted into four bytes so that
		 * the binary point is located between the second and the third
		 * byte fromat (that is Q16.16)
		 *
		 * ff = (freq << 16) / 8000
		 *
		 * Win10 and OSX UAC2 drivers require number of samples per packet
		 * in order to honor the feedback value.
		 * Linux snd-usb-audio detects the applied bit-shift automatically.
		 */
		ep_desc = out_ep->desc;
		freq <<= 4 + (ep_desc->bInterval - 1);
	}

	ff = DIV_ROUND_CLOSEST_ULL((freq * pitch), 1953125);

	*(__le32 *)buf = cpu_to_le32(ff);
}

static void u_audio_iso_complete(struct usb_ep *ep, struct usb_request *req)
{
	unsigned int pending;
	unsigned int hw_ptr;
	int status = req->status;
	struct snd_pcm_substream *substream;
	struct snd_pcm_runtime *runtime;
	struct uac_rtd_params *prm = req->context;
	struct snd_uac_chip *uac = prm->uac;
	struct g_audio *audio_dev = uac->audio_dev;
	struct uac_params *params = &audio_dev->params;
	unsigned int frames, p_pktsize;
	unsigned long long pitched_rate_mil, p_pktsize_residue_mil,
			residue_frames_mil, div_result;

	/* i/f shutting down */
	if (!prm->ep_enabled) {
		usb_ep_free_request(ep, req);
		return;
	}

	if (req->status == -ESHUTDOWN)
		return;

	/*
	 * We can't really do much about bad xfers.
	 * Afterall, the ISOCH xfers could fail legitimately.
	 */
	if (status)
		pr_debug("%s: iso_complete status(%d) %d/%d\n",
			__func__, status, req->actual, req->length);

	substream = prm->ss;

	/* Do nothing if ALSA isn't active */
	if (!substream)
		goto exit;

	snd_pcm_stream_lock(substream);

	runtime = substream->runtime;
	if (!runtime || !snd_pcm_running(substream)) {
		snd_pcm_stream_unlock(substream);
		goto exit;
	}

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		/*
		 * For each IN packet, take the quotient of the current data
		 * rate and the endpoint's interval as the base packet size.
		 * If there is a residue from this division, add it to the
		 * residue accumulator.
		 */
		unsigned long long p_interval_mil = uac->p_interval * 1000000ULL;

		pitched_rate_mil = (unsigned long long)
				params->p_srate * prm->pitch;
		div_result = pitched_rate_mil;
		do_div(div_result, uac->p_interval);
		do_div(div_result, 1000000);
		frames = (unsigned int) div_result;

		pr_debug("p_srate %d, pitch %d, interval_mil %llu, frames %d\n",
				params->p_srate, prm->pitch, p_interval_mil, frames);

		p_pktsize = min_t(unsigned int,
					uac->p_framesize * frames,
					ep->maxpacket);

		if (p_pktsize < ep->maxpacket) {
			residue_frames_mil = pitched_rate_mil - frames * p_interval_mil;
			p_pktsize_residue_mil = uac->p_framesize * residue_frames_mil;
		} else
			p_pktsize_residue_mil = 0;

		req->length = p_pktsize;
		uac->p_residue_mil += p_pktsize_residue_mil;

		/*
		 * Whenever there are more bytes in the accumulator p_residue_mil than we
		 * need to add one more sample frame, increase this packet's
		 * size and decrease the accumulator.
		 */
		div_result = uac->p_residue_mil;
		do_div(div_result, uac->p_interval);
		do_div(div_result, 1000000);
		if ((unsigned int) div_result >= uac->p_framesize) {
			req->length += uac->p_framesize;
			uac->p_residue_mil -= uac->p_framesize * p_interval_mil;
			pr_debug("increased req length to %d\n", req->length);
		}
		pr_debug("remains uac->p_residue_mil %llu\n", uac->p_residue_mil);

		req->actual = req->length;
	}

	hw_ptr = prm->hw_ptr;

	/* Pack USB load in ALSA ring buffer */
	pending = runtime->dma_bytes - hw_ptr;

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		if (unlikely(pending < req->actual)) {
			memcpy(req->buf, runtime->dma_area + hw_ptr, pending);
			memcpy(req->buf + pending, runtime->dma_area,
			       req->actual - pending);
		} else {
			memcpy(req->buf, runtime->dma_area + hw_ptr,
			       req->actual);
		}
	} else {
		if (unlikely(pending < req->actual)) {
			memcpy(runtime->dma_area + hw_ptr, req->buf, pending);
			memcpy(runtime->dma_area, req->buf + pending,
			       req->actual - pending);
		} else {
			memcpy(runtime->dma_area + hw_ptr, req->buf,
			       req->actual);
		}
	}

	/* update hw_ptr after data is copied to memory */
	prm->hw_ptr = (hw_ptr + req->actual) % runtime->dma_bytes;
	hw_ptr = prm->hw_ptr;
	snd_pcm_stream_unlock(substream);

	if ((hw_ptr % snd_pcm_lib_period_bytes(substream)) < req->actual)
		snd_pcm_period_elapsed(substream);

exit:
	if (usb_ep_queue(ep, req, GFP_ATOMIC))
		dev_err(uac->card->dev, "%d Error!\n", __LINE__);
}

static void u_audio_iso_fback_complete(struct usb_ep *ep,
				       struct usb_request *req)
{
	struct uac_rtd_params *prm = req->context;
	struct snd_uac_chip *uac = prm->uac;
	struct g_audio *audio_dev = uac->audio_dev;
	struct uac_params *params = &audio_dev->params;
	int status = req->status;

	/* i/f shutting down */
	if (!prm->fb_ep_enabled) {
		kfree(req->buf);
		usb_ep_free_request(ep, req);
		return;
	}

	if (req->status == -ESHUTDOWN)
		return;

	/*
	 * We can't really do much about bad xfers.
	 * Afterall, the ISOCH xfers could fail legitimately.
	 */
	if (status)
		pr_debug("%s: iso_complete status(%d) %d/%d\n",
			__func__, status, req->actual, req->length);

	u_audio_set_fback_frequency(audio_dev->gadget->speed, audio_dev->out_ep,
				    params->c_srate, prm->pitch,
				    req->buf);

	if (usb_ep_queue(ep, req, GFP_ATOMIC))
		dev_err(uac->card->dev, "%d Error!\n", __LINE__);
}

static int uac_pcm_trigger(struct snd_pcm_substream *substream, int cmd)
{
	struct snd_uac_chip *uac = snd_pcm_substream_chip(substream);
	struct uac_rtd_params *prm;
	struct g_audio *audio_dev;
	struct uac_params *params;
	int err = 0;

	audio_dev = uac->audio_dev;
	params = &audio_dev->params;

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		prm = &uac->p_prm;
	else
		prm = &uac->c_prm;

	/* Reset */
	prm->hw_ptr = 0;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_RESUME:
		prm->ss = substream;
		break;
	case SNDRV_PCM_TRIGGER_STOP:
	case SNDRV_PCM_TRIGGER_SUSPEND:
		prm->ss = NULL;
		break;
	default:
		err = -EINVAL;
	}

	/* Clear buffer after Play stops */
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK && !prm->ss)
		memset(prm->rbuf, 0, prm->max_psize * params->req_number);

	return err;
}

static snd_pcm_uframes_t uac_pcm_pointer(struct snd_pcm_substream *substream)
{
	struct snd_uac_chip *uac = snd_pcm_substream_chip(substream);
	struct uac_rtd_params *prm;

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		prm = &uac->p_prm;
	else
		prm = &uac->c_prm;

	return bytes_to_frames(substream->runtime, prm->hw_ptr);
}

static u64 uac_ssize_to_fmt(int ssize)
{
	u64 ret;

	switch (ssize) {
	case 3:
		ret = SNDRV_PCM_FMTBIT_S24_3LE;
		break;
	case 4:
		ret = SNDRV_PCM_FMTBIT_S32_LE;
		break;
	default:
		ret = SNDRV_PCM_FMTBIT_S16_LE;
		break;
	}

	return ret;
}

static int uac_pcm_open(struct snd_pcm_substream *substream)
{
	struct snd_uac_chip *uac = snd_pcm_substream_chip(substream);
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct g_audio *audio_dev;
	struct uac_params *params;
	int p_ssize, c_ssize;
	int p_srate, c_srate;
	int p_chmask, c_chmask;

	audio_dev = uac->audio_dev;
	params = &audio_dev->params;
	p_ssize = params->p_ssize;
	c_ssize = params->c_ssize;
	p_srate = params->p_srate;
	c_srate = params->c_srate;
	p_chmask = params->p_chmask;
	c_chmask = params->c_chmask;
	uac->p_residue_mil = 0;

	runtime->hw = uac_pcm_hardware;

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		runtime->hw.rate_min = p_srate;
		runtime->hw.formats = uac_ssize_to_fmt(p_ssize);
		runtime->hw.channels_min = num_channels(p_chmask);
		runtime->hw.period_bytes_min = 2 * uac->p_prm.max_psize
						/ runtime->hw.periods_min;
	} else {
		runtime->hw.rate_min = c_srate;
		runtime->hw.formats = uac_ssize_to_fmt(c_ssize);
		runtime->hw.channels_min = num_channels(c_chmask);
		runtime->hw.period_bytes_min = 2 * uac->c_prm.max_psize
						/ runtime->hw.periods_min;
	}

	runtime->hw.rate_max = runtime->hw.rate_min;
	runtime->hw.channels_max = runtime->hw.channels_min;

	snd_pcm_hw_constraint_integer(runtime, SNDRV_PCM_HW_PARAM_PERIODS);

	return 0;
}

/* ALSA cries without these function pointers */
static int uac_pcm_null(struct snd_pcm_substream *substream)
{
	return 0;
}

static const struct snd_pcm_ops uac_pcm_ops = {
	.open = uac_pcm_open,
	.close = uac_pcm_null,
	.trigger = uac_pcm_trigger,
	.pointer = uac_pcm_pointer,
	.prepare = uac_pcm_null,
};

static inline void free_ep(struct uac_rtd_params *prm, struct usb_ep *ep)
{
	struct snd_uac_chip *uac = prm->uac;
	struct g_audio *audio_dev;
	struct uac_params *params;
	int i;

	if (!prm->ep_enabled)
		return;

	audio_dev = uac->audio_dev;
	params = &audio_dev->params;

	for (i = 0; i < params->req_number; i++) {
		if (prm->reqs[i]) {
			if (usb_ep_dequeue(ep, prm->reqs[i]))
				usb_ep_free_request(ep, prm->reqs[i]);
			/*
			 * If usb_ep_dequeue() cannot successfully dequeue the
			 * request, the request will be freed by the completion
			 * callback.
			 */

			prm->reqs[i] = NULL;
		}
	}

	prm->ep_enabled = false;

	if (usb_ep_disable(ep))
		dev_err(uac->card->dev, "%s:%d Error!\n", __func__, __LINE__);
}

static inline void free_ep_fback(struct uac_rtd_params *prm, struct usb_ep *ep)
{
	struct snd_uac_chip *uac = prm->uac;

	if (!prm->fb_ep_enabled)
		return;

	if (prm->req_fback) {
		if (usb_ep_dequeue(ep, prm->req_fback)) {
			kfree(prm->req_fback->buf);
			usb_ep_free_request(ep, prm->req_fback);
		}
		prm->req_fback = NULL;
	}

	prm->fb_ep_enabled = false;

	if (usb_ep_disable(ep))
		dev_err(uac->card->dev, "%s:%d Error!\n", __func__, __LINE__);
}

int u_audio_start_capture(struct g_audio *audio_dev)
{
	struct snd_uac_chip *uac = audio_dev->uac;
	struct usb_gadget *gadget = audio_dev->gadget;
	struct device *dev = &gadget->dev;
	struct usb_request *req, *req_fback;
	struct usb_ep *ep, *ep_fback;
	struct uac_rtd_params *prm;
	struct uac_params *params = &audio_dev->params;
	int req_len, i;

	ep = audio_dev->out_ep;
	prm = &uac->c_prm;
	config_ep_by_speed(gadget, &audio_dev->func, ep);
	req_len = ep->maxpacket;

	prm->ep_enabled = true;
	usb_ep_enable(ep);

	for (i = 0; i < params->req_number; i++) {
		if (!prm->reqs[i]) {
			req = usb_ep_alloc_request(ep, GFP_ATOMIC);
			if (req == NULL)
				return -ENOMEM;

			prm->reqs[i] = req;

			req->zero = 0;
			req->context = prm;
			req->length = req_len;
			req->complete = u_audio_iso_complete;
			req->buf = prm->rbuf + i * ep->maxpacket;
		}

		if (usb_ep_queue(ep, prm->reqs[i], GFP_ATOMIC))
			dev_err(dev, "%s:%d Error!\n", __func__, __LINE__);
	}

	ep_fback = audio_dev->in_ep_fback;
	if (!ep_fback)
		return 0;

	/* Setup feedback endpoint */
	config_ep_by_speed(gadget, &audio_dev->func, ep_fback);
	prm->fb_ep_enabled = true;
	usb_ep_enable(ep_fback);
	req_len = ep_fback->maxpacket;

	req_fback = usb_ep_alloc_request(ep_fback, GFP_ATOMIC);
	if (req_fback == NULL)
		return -ENOMEM;

	prm->req_fback = req_fback;
	req_fback->zero = 0;
	req_fback->context = prm;
	req_fback->length = req_len;
	req_fback->complete = u_audio_iso_fback_complete;

	req_fback->buf = kzalloc(req_len, GFP_ATOMIC);
	if (!req_fback->buf)
		return -ENOMEM;

	/*
	 * Configure the feedback endpoint's reported frequency.
	 * Always start with original frequency since its deviation can't
	 * be meauserd at start of playback
	 */
	prm->pitch = 1000000;
	u_audio_set_fback_frequency(audio_dev->gadget->speed, ep,
				    params->c_srate, prm->pitch,
				    req_fback->buf);

	if (usb_ep_queue(ep_fback, req_fback, GFP_ATOMIC))
		dev_err(dev, "%s:%d Error!\n", __func__, __LINE__);

	return 0;
}
EXPORT_SYMBOL_GPL(u_audio_start_capture);

void u_audio_stop_capture(struct g_audio *audio_dev)
{
	struct snd_uac_chip *uac = audio_dev->uac;

	if (audio_dev->in_ep_fback)
		free_ep_fback(&uac->c_prm, audio_dev->in_ep_fback);
	free_ep(&uac->c_prm, audio_dev->out_ep);
}
EXPORT_SYMBOL_GPL(u_audio_stop_capture);

int u_audio_start_playback(struct g_audio *audio_dev)
{
	struct snd_uac_chip *uac = audio_dev->uac;
	struct usb_gadget *gadget = audio_dev->gadget;
	struct device *dev = &gadget->dev;
	struct usb_request *req;
	struct usb_ep *ep;
	struct uac_rtd_params *prm;
	struct uac_params *params = &audio_dev->params;
	unsigned int factor;
	const struct usb_endpoint_descriptor *ep_desc;
	int req_len, i;
	unsigned int p_pktsize;

	ep = audio_dev->in_ep;
	prm = &uac->p_prm;
	config_ep_by_speed(gadget, &audio_dev->func, ep);

	ep_desc = ep->desc;
	/*
	 * Always start with original frequency
	 */
	prm->pitch = 1000000;

	/* pre-calculate the playback endpoint's interval */
	if (gadget->speed == USB_SPEED_FULL)
		factor = 1000;
	else
		factor = 8000;

	/* pre-compute some values for iso_complete() */
	uac->p_framesize = params->p_ssize *
			    num_channels(params->p_chmask);
	uac->p_interval = factor / (1 << (ep_desc->bInterval - 1));
	p_pktsize = min_t(unsigned int,
				uac->p_framesize *
					(params->p_srate / uac->p_interval),
				ep->maxpacket);

	req_len = p_pktsize;
	uac->p_residue_mil = 0;

	prm->ep_enabled = true;
	usb_ep_enable(ep);

	for (i = 0; i < params->req_number; i++) {
		if (!prm->reqs[i]) {
			req = usb_ep_alloc_request(ep, GFP_ATOMIC);
			if (req == NULL)
				return -ENOMEM;

			prm->reqs[i] = req;

			req->zero = 0;
			req->context = prm;
			req->length = req_len;
			req->complete = u_audio_iso_complete;
			req->buf = prm->rbuf + i * ep->maxpacket;
		}

		if (usb_ep_queue(ep, prm->reqs[i], GFP_ATOMIC))
			dev_err(dev, "%s:%d Error!\n", __func__, __LINE__);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(u_audio_start_playback);

void u_audio_stop_playback(struct g_audio *audio_dev)
{
	struct snd_uac_chip *uac = audio_dev->uac;

	free_ep(&uac->p_prm, audio_dev->in_ep);
}
EXPORT_SYMBOL_GPL(u_audio_stop_playback);

int u_audio_get_volume(struct g_audio *audio_dev, int playback, s16 *val)
{
	struct snd_uac_chip *uac = audio_dev->uac;
	struct uac_rtd_params *prm;
	unsigned long flags;

	if (playback)
		prm = &uac->p_prm;
	else
		prm = &uac->c_prm;

	spin_lock_irqsave(&prm->lock, flags);
	*val = prm->volume;
	spin_unlock_irqrestore(&prm->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(u_audio_get_volume);

int u_audio_set_volume(struct g_audio *audio_dev, int playback, s16 val)
{
	struct snd_uac_chip *uac = audio_dev->uac;
	struct uac_rtd_params *prm;
	unsigned long flags;
	int change = 0;

	if (playback)
		prm = &uac->p_prm;
	else
		prm = &uac->c_prm;

	spin_lock_irqsave(&prm->lock, flags);
	val = clamp(val, prm->volume_min, prm->volume_max);
	if (prm->volume != val) {
		prm->volume = val;
		change = 1;
	}
	spin_unlock_irqrestore(&prm->lock, flags);

	if (change)
		snd_ctl_notify(uac->card, SNDRV_CTL_EVENT_MASK_VALUE,
				&prm->snd_kctl_volume->id);

	return 0;
}
EXPORT_SYMBOL_GPL(u_audio_set_volume);

int u_audio_get_mute(struct g_audio *audio_dev, int playback, int *val)
{
	struct snd_uac_chip *uac = audio_dev->uac;
	struct uac_rtd_params *prm;
	unsigned long flags;

	if (playback)
		prm = &uac->p_prm;
	else
		prm = &uac->c_prm;

	spin_lock_irqsave(&prm->lock, flags);
	*val = prm->mute;
	spin_unlock_irqrestore(&prm->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(u_audio_get_mute);

int u_audio_set_mute(struct g_audio *audio_dev, int playback, int val)
{
	struct snd_uac_chip *uac = audio_dev->uac;
	struct uac_rtd_params *prm;
	unsigned long flags;
	int change = 0;
	int mute;

	if (playback)
		prm = &uac->p_prm;
	else
		prm = &uac->c_prm;

	mute = val ? 1 : 0;

	spin_lock_irqsave(&prm->lock, flags);
	if (prm->mute != mute) {
		prm->mute = mute;
		change = 1;
	}
	spin_unlock_irqrestore(&prm->lock, flags);

	if (change)
		snd_ctl_notify(uac->card, SNDRV_CTL_EVENT_MASK_VALUE,
			       &prm->snd_kctl_mute->id);

	return 0;
}
EXPORT_SYMBOL_GPL(u_audio_set_mute);


static int u_audio_pitch_info(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_info *uinfo)
{
	struct uac_rtd_params *prm = snd_kcontrol_chip(kcontrol);
	struct snd_uac_chip *uac = prm->uac;
	struct g_audio *audio_dev = uac->audio_dev;
	struct uac_params *params = &audio_dev->params;
	unsigned int pitch_min, pitch_max;

	pitch_min = (1000 - FBACK_SLOW_MAX) * 1000;
	pitch_max = (1000 + params->fb_max) * 1000;

	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
	uinfo->count = 1;
	uinfo->value.integer.min = pitch_min;
	uinfo->value.integer.max = pitch_max;
	uinfo->value.integer.step = 1;
	return 0;
}

static int u_audio_pitch_get(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_value *ucontrol)
{
	struct uac_rtd_params *prm = snd_kcontrol_chip(kcontrol);

	ucontrol->value.integer.value[0] = prm->pitch;

	return 0;
}

static int u_audio_pitch_put(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	struct uac_rtd_params *prm = snd_kcontrol_chip(kcontrol);
	struct snd_uac_chip *uac = prm->uac;
	struct g_audio *audio_dev = uac->audio_dev;
	struct uac_params *params = &audio_dev->params;
	unsigned int val;
	unsigned int pitch_min, pitch_max;
	int change = 0;

	pitch_min = (1000 - FBACK_SLOW_MAX) * 1000;
	pitch_max = (1000 + params->fb_max) * 1000;

	val = ucontrol->value.integer.value[0];

	if (val < pitch_min)
		val = pitch_min;
	if (val > pitch_max)
		val = pitch_max;

	if (prm->pitch != val) {
		prm->pitch = val;
		change = 1;
	}

	return change;
}

static int u_audio_mute_info(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_info *uinfo)
{
	uinfo->type = SNDRV_CTL_ELEM_TYPE_BOOLEAN;
	uinfo->count = 1;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = 1;
	uinfo->value.integer.step = 1;

	return 0;
}

static int u_audio_mute_get(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_value *ucontrol)
{
	struct uac_rtd_params *prm = snd_kcontrol_chip(kcontrol);
	unsigned long flags;

	spin_lock_irqsave(&prm->lock, flags);
	ucontrol->value.integer.value[0] = !prm->mute;
	spin_unlock_irqrestore(&prm->lock, flags);

	return 0;
}

static int u_audio_mute_put(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	struct uac_rtd_params *prm = snd_kcontrol_chip(kcontrol);
	struct snd_uac_chip *uac = prm->uac;
	struct g_audio *audio_dev = uac->audio_dev;
	unsigned int val;
	unsigned long flags;
	int change = 0;

	val = !ucontrol->value.integer.value[0];

	spin_lock_irqsave(&prm->lock, flags);
	if (val != prm->mute) {
		prm->mute = val;
		change = 1;
	}
	spin_unlock_irqrestore(&prm->lock, flags);

	if (change && audio_dev->notify)
		audio_dev->notify(audio_dev, prm->fu_id, UAC_FU_MUTE);

	return change;
}

/*
 * TLV callback for mixer volume controls
 */
static int u_audio_volume_tlv(struct snd_kcontrol *kcontrol, int op_flag,
			 unsigned int size, unsigned int __user *_tlv)
{
	struct uac_rtd_params *prm = snd_kcontrol_chip(kcontrol);
	DECLARE_TLV_DB_MINMAX(scale, 0, 0);

	if (size < sizeof(scale))
		return -ENOMEM;

	/* UAC volume resolution is 1/256 dB, TLV is 1/100 dB */
	scale[2] = (prm->volume_min * 100) / 256;
	scale[3] = (prm->volume_max * 100) / 256;
	if (copy_to_user(_tlv, scale, sizeof(scale)))
		return -EFAULT;

	return 0;
}

static int u_audio_volume_info(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_info *uinfo)
{
	struct uac_rtd_params *prm = snd_kcontrol_chip(kcontrol);

	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
	uinfo->count = 1;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max =
		(prm->volume_max - prm->volume_min + prm->volume_res - 1)
		/ prm->volume_res;
	uinfo->value.integer.step = 1;

	return 0;
}

static int u_audio_volume_get(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_value *ucontrol)
{
	struct uac_rtd_params *prm = snd_kcontrol_chip(kcontrol);
	unsigned long flags;

	spin_lock_irqsave(&prm->lock, flags);
	ucontrol->value.integer.value[0] =
			(prm->volume - prm->volume_min) / prm->volume_res;
	spin_unlock_irqrestore(&prm->lock, flags);

	return 0;
}

static int u_audio_volume_put(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	struct uac_rtd_params *prm = snd_kcontrol_chip(kcontrol);
	struct snd_uac_chip *uac = prm->uac;
	struct g_audio *audio_dev = uac->audio_dev;
	unsigned int val;
	s16 volume;
	unsigned long flags;
	int change = 0;

	val = ucontrol->value.integer.value[0];

	spin_lock_irqsave(&prm->lock, flags);
	volume = (val * prm->volume_res) + prm->volume_min;
	volume = clamp(volume, prm->volume_min, prm->volume_max);
	if (volume != prm->volume) {
		prm->volume = volume;
		change = 1;
	}
	spin_unlock_irqrestore(&prm->lock, flags);

	if (change && audio_dev->notify)
		audio_dev->notify(audio_dev, prm->fu_id, UAC_FU_VOLUME);

	return change;
}


static struct snd_kcontrol_new u_audio_controls[]  = {
  [UAC_FBACK_CTRL] {
    .iface =        SNDRV_CTL_ELEM_IFACE_PCM,
    .name =         "Capture Pitch 1000000",
    .info =         u_audio_pitch_info,
    .get =          u_audio_pitch_get,
    .put =          u_audio_pitch_put,
  },
	[UAC_P_PITCH_CTRL] {
		.iface =        SNDRV_CTL_ELEM_IFACE_PCM,
		.name =         "Playback Pitch 1000000",
		.info =         u_audio_pitch_info,
		.get =          u_audio_pitch_get,
		.put =          u_audio_pitch_put,
	},
  [UAC_MUTE_CTRL] {
		.iface =	SNDRV_CTL_ELEM_IFACE_MIXER,
		.name =		"", /* will be filled later */
		.info =		u_audio_mute_info,
		.get =		u_audio_mute_get,
		.put =		u_audio_mute_put,
	},
	[UAC_VOLUME_CTRL] {
		.iface =	SNDRV_CTL_ELEM_IFACE_MIXER,
		.name =		"", /* will be filled later */
		.info =		u_audio_volume_info,
		.get =		u_audio_volume_get,
		.put =		u_audio_volume_put,
	},
};

int g_audio_setup(struct g_audio *g_audio, const char *pcm_name,
					const char *card_name)
{
	struct snd_uac_chip *uac;
	struct snd_card *card;
	struct snd_pcm *pcm;
	struct snd_kcontrol *kctl;
	struct uac_params *params;
	int p_chmask, c_chmask;
	int i, err;

	if (!g_audio)
		return -EINVAL;

	uac = kzalloc(sizeof(*uac), GFP_KERNEL);
	if (!uac)
		return -ENOMEM;
	g_audio->uac = uac;
	uac->audio_dev = g_audio;

	params = &g_audio->params;
	p_chmask = params->p_chmask;
	c_chmask = params->c_chmask;

	if (c_chmask) {
		struct uac_rtd_params *prm = &uac->c_prm;

    spin_lock_init(&prm->lock);
    uac->c_prm.uac = uac;
		prm->max_psize = g_audio->out_ep_maxpsize;

		prm->reqs = kcalloc(params->req_number,
				    sizeof(struct usb_request *),
				    GFP_KERNEL);
		if (!prm->reqs) {
			err = -ENOMEM;
			goto fail;
		}

		prm->rbuf = kcalloc(params->req_number, prm->max_psize,
				GFP_KERNEL);
		if (!prm->rbuf) {
			prm->max_psize = 0;
			err = -ENOMEM;
			goto fail;
		}
	}

	if (p_chmask) {
		struct uac_rtd_params *prm = &uac->p_prm;

		spin_lock_init(&prm->lock);
		uac->p_prm.uac = uac;
		prm->max_psize = g_audio->in_ep_maxpsize;

		prm->reqs = kcalloc(params->req_number,
				    sizeof(struct usb_request *),
				    GFP_KERNEL);
		if (!prm->reqs) {
			err = -ENOMEM;
			goto fail;
		}

		prm->rbuf = kcalloc(params->req_number, prm->max_psize,
				GFP_KERNEL);
		if (!prm->rbuf) {
			prm->max_psize = 0;
			err = -ENOMEM;
			goto fail;
		}
	}

	/* Choose any slot, with no id */
	err = snd_card_new(&g_audio->gadget->dev,
			-1, NULL, THIS_MODULE, 0, &card);
	if (err < 0)
		goto fail;

	uac->card = card;

	/*
	 * Create first PCM device
	 * Create a substream only for non-zero channel streams
	 */
	err = snd_pcm_new(uac->card, pcm_name, 0,
			       p_chmask ? 1 : 0, c_chmask ? 1 : 0, &pcm);
	if (err < 0)
		goto snd_fail;

	strscpy(pcm->name, pcm_name, sizeof(pcm->name));
	pcm->private_data = uac;
	uac->pcm = pcm;

	snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_PLAYBACK, &uac_pcm_ops);
	snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_CAPTURE, &uac_pcm_ops);

	/*
	 * Create mixer and controls
	 * Create only if it's required on USB side
	 */
	if ((c_chmask && g_audio->in_ep_fback)
			|| (p_chmask && params->p_fu.id)
			|| (c_chmask && params->c_fu.id))
		strscpy(card->mixername, card_name, sizeof(card->driver));

	if (c_chmask && g_audio->in_ep_fback) {
		kctl = snd_ctl_new1(&u_audio_controls[UAC_FBACK_CTRL],
				    &uac->c_prm);
		if (!kctl) {
			err = -ENOMEM;
			goto snd_fail;
		}

		kctl->id.device = pcm->device;
		kctl->id.subdevice = 0;

		err = snd_ctl_add(card, kctl);
		if (err < 0)
			goto snd_fail;
	}

	if (p_chmask) {
		kctl = snd_ctl_new1(&u_audio_controls[UAC_P_PITCH_CTRL],
				    &uac->p_prm);
		if (!kctl) {
			err = -ENOMEM;
			goto snd_fail;
		}

		kctl->id.device = pcm->device;
		kctl->id.subdevice = 0;

		err = snd_ctl_add(card, kctl);
		if (err < 0)
			goto snd_fail;
	}

	for (i = 0; i <= SNDRV_PCM_STREAM_LAST; i++) {
		struct uac_rtd_params *prm;
		struct uac_fu_params *fu;
		char ctrl_name[24];
		char *direction;

		if (!pcm->streams[i].substream_count)
			continue;

		if (i == SNDRV_PCM_STREAM_PLAYBACK) {
			prm = &uac->p_prm;
			fu = &params->p_fu;
			direction = "Playback";
		} else {
			prm = &uac->c_prm;
			fu = &params->c_fu;
			direction = "Capture";
		}

		prm->fu_id = fu->id;

		if (fu->mute_present) {
			snprintf(ctrl_name, sizeof(ctrl_name),
					"PCM %s Switch", direction);

			u_audio_controls[UAC_MUTE_CTRL].name = ctrl_name;

			kctl = snd_ctl_new1(&u_audio_controls[UAC_MUTE_CTRL],
					    prm);
			if (!kctl) {
				err = -ENOMEM;
				goto snd_fail;
			}

			kctl->id.device = pcm->device;
			kctl->id.subdevice = 0;

			err = snd_ctl_add(card, kctl);
			if (err < 0)
				goto snd_fail;
			prm->snd_kctl_mute = kctl;
			prm->mute = 0;
		}

		if (fu->volume_present) {
			snprintf(ctrl_name, sizeof(ctrl_name),
					"PCM %s Volume", direction);

			u_audio_controls[UAC_VOLUME_CTRL].name = ctrl_name;

			kctl = snd_ctl_new1(&u_audio_controls[UAC_VOLUME_CTRL],
					    prm);
			if (!kctl) {
				err = -ENOMEM;
				goto snd_fail;
			}

			kctl->id.device = pcm->device;
			kctl->id.subdevice = 0;


			kctl->tlv.c = u_audio_volume_tlv;
			kctl->vd[0].access |= SNDRV_CTL_ELEM_ACCESS_TLV_READ |
					SNDRV_CTL_ELEM_ACCESS_TLV_CALLBACK;

			err = snd_ctl_add(card, kctl);
			if (err < 0)
				goto snd_fail;
			prm->snd_kctl_volume = kctl;
			prm->volume = fu->volume_max;
			prm->volume_max = fu->volume_max;
			prm->volume_min = fu->volume_min;
			prm->volume_res = fu->volume_res;
		}
	}

	strscpy(card->driver, card_name, sizeof(card->driver));
	strscpy(card->shortname, card_name, sizeof(card->shortname));
	sprintf(card->longname, "%s %i", card_name, card->dev->id);

	snd_pcm_set_managed_buffer_all(pcm, SNDRV_DMA_TYPE_CONTINUOUS,
				       NULL, 0, BUFF_SIZE_MAX);

	err = snd_card_register(card);

	if (!err)
		return 0;

snd_fail:
	snd_card_free(card);
fail:
	kfree(uac->p_prm.reqs);
	kfree(uac->c_prm.reqs);
	kfree(uac->p_prm.rbuf);
	kfree(uac->c_prm.rbuf);
	kfree(uac);

	return err;
}
EXPORT_SYMBOL_GPL(g_audio_setup);

void g_audio_cleanup(struct g_audio *g_audio)
{
	struct snd_uac_chip *uac;
	struct snd_card *card;

	if (!g_audio || !g_audio->uac)
		return;

	uac = g_audio->uac;
	card = uac->card;
	if (card)
		snd_card_free(card);

	kfree(uac->p_prm.reqs);
	kfree(uac->c_prm.reqs);
	kfree(uac->p_prm.rbuf);
	kfree(uac->c_prm.rbuf);
	kfree(uac);
}
EXPORT_SYMBOL_GPL(g_audio_cleanup);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("USB gadget \"ALSA sound card\" utilities");
MODULE_AUTHOR("Ruslan Bilovol");
