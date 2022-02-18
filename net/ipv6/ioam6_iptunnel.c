// SPDX-License-Identifier: GPL-2.0+
/*
 *  IPv6 IOAM Lightweight Tunnel implementation
 *
 *  Author:
 *  Justin Iurman <justin.iurman@uliege.be>
 */

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/in6.h>
#include <linux/ioam6.h>
#include <linux/ioam6_iptunnel.h>
#include <net/dst.h>
#include <net/sock.h>
#include <net/lwtunnel.h>
#include <net/ioam6.h>
#include <net/netlink.h>
#include <net/ipv6.h>
#include <net/dst_cache.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>

#define IOAM6_MASK_SHORT_FIELDS 0xff100000
#define IOAM6_MASK_WIDE_FIELDS 0xe00000

struct ioam6_lwt_encap {
	struct ipv6_hopopt_hdr eh;
	u8 pad[2];			/* 2-octet padding for 4n-alignment */
	struct ioam6_hdr ioamh;
	struct ioam6_trace_hdr traceh;
} __packed;

struct ioam6_lwt {
	struct dst_cache cache;
	u8 mode;
	struct in6_addr tundst;
	struct ioam6_lwt_encap	tuninfo;
};

static struct ioam6_lwt *ioam6_lwt_state(struct lwtunnel_state *lwt)
{
	return (struct ioam6_lwt *)lwt->data;
}

static struct ioam6_lwt_encap *ioam6_lwt_info(struct lwtunnel_state *lwt)
{
	return &ioam6_lwt_state(lwt)->tuninfo;
}

static struct ioam6_trace_hdr *ioam6_lwt_trace(struct lwtunnel_state *lwt)
{
	return &(ioam6_lwt_state(lwt)->tuninfo.traceh);
}

static const struct nla_policy ioam6_iptunnel_policy[IOAM6_IPTUNNEL_MAX + 1] = {
	[IOAM6_IPTUNNEL_MODE]	= NLA_POLICY_RANGE(NLA_U8,
						   IOAM6_IPTUNNEL_MODE_MIN,
						   IOAM6_IPTUNNEL_MODE_MAX),
	[IOAM6_IPTUNNEL_DST]	= NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
	[IOAM6_IPTUNNEL_TRACE]	= NLA_POLICY_EXACT_LEN(sizeof(struct ioam6_trace_hdr)),
};

static bool ioam6_validate_trace_hdr(struct ioam6_trace_hdr *trace)
{
	u32 fields;

	if (!trace->type_be32 || !trace->remlen ||
	    trace->remlen > IOAM6_TRACE_DATA_SIZE_MAX / 4 ||
	    trace->type.bit12 | trace->type.bit13 | trace->type.bit14 |
	    trace->type.bit15 | trace->type.bit16 | trace->type.bit17 |
	    trace->type.bit18 | trace->type.bit19 | trace->type.bit20 |
	    trace->type.bit21)
		return false;

	trace->nodelen = 0;
	fields = be32_to_cpu(trace->type_be32);

	trace->nodelen += hweight32(fields & IOAM6_MASK_SHORT_FIELDS)
				* (sizeof(__be32) / 4);
	trace->nodelen += hweight32(fields & IOAM6_MASK_WIDE_FIELDS)
				* (sizeof(__be64) / 4);

	return true;
}

static int ioam6_build_state(struct net *net, struct nlattr *nla,
			     unsigned int family, const void *cfg,
			     struct lwtunnel_state **ts,
			     struct netlink_ext_ack *extack)
{
	struct nlattr *tb[IOAM6_IPTUNNEL_MAX + 1];
	struct ioam6_lwt_encap *tuninfo;
	struct ioam6_trace_hdr *trace;
	struct lwtunnel_state *lwt;
	struct ioam6_lwt *ilwt;
	int len_aligned, err;
	u8 mode;

	if (family != AF_INET6)
		return -EINVAL;

	err = nla_parse_nested(tb, IOAM6_IPTUNNEL_MAX, nla,
			       ioam6_iptunnel_policy, extack);
	if (err < 0)
		return err;

	if (!tb[IOAM6_IPTUNNEL_MODE])
		mode = IOAM6_IPTUNNEL_MODE_INLINE;
	else
		mode = nla_get_u8(tb[IOAM6_IPTUNNEL_MODE]);

	if (!tb[IOAM6_IPTUNNEL_DST] && mode != IOAM6_IPTUNNEL_MODE_INLINE) {
		NL_SET_ERR_MSG(extack, "this mode needs a tunnel destination");
		return -EINVAL;
	}

	if (!tb[IOAM6_IPTUNNEL_TRACE]) {
		NL_SET_ERR_MSG(extack, "missing trace");
		return -EINVAL;
	}

	trace = nla_data(tb[IOAM6_IPTUNNEL_TRACE]);
	if (!ioam6_validate_trace_hdr(trace)) {
		NL_SET_ERR_MSG_ATTR(extack, tb[IOAM6_IPTUNNEL_TRACE],
				    "invalid trace validation");
		return -EINVAL;
	}

	len_aligned = ALIGN(trace->remlen * 4, 8);
	lwt = lwtunnel_state_alloc(sizeof(*ilwt) + len_aligned);
	if (!lwt)
		return -ENOMEM;

	ilwt = ioam6_lwt_state(lwt);
	err = dst_cache_init(&ilwt->cache, GFP_ATOMIC);
	if (err) {
		kfree(lwt);
		return err;
	}

	ilwt->mode = mode;
	if (tb[IOAM6_IPTUNNEL_DST])
		ilwt->tundst = nla_get_in6_addr(tb[IOAM6_IPTUNNEL_DST]);

	tuninfo = ioam6_lwt_info(lwt);
	tuninfo->eh.hdrlen = ((sizeof(*tuninfo) + len_aligned) >> 3) - 1;
	tuninfo->pad[0] = IPV6_TLV_PADN;
	tuninfo->ioamh.type = IOAM6_TYPE_PREALLOC;
	tuninfo->ioamh.opt_type = IPV6_TLV_IOAM;
	tuninfo->ioamh.opt_len = sizeof(tuninfo->ioamh) - 2 + sizeof(*trace)
					+ trace->remlen * 4;

	memcpy(&tuninfo->traceh, trace, sizeof(*trace));

	if (len_aligned - trace->remlen * 4) {
		tuninfo->traceh.data[trace->remlen * 4] = IPV6_TLV_PADN;
		tuninfo->traceh.data[trace->remlen * 4 + 1] = 2;
	}

	lwt->type = LWTUNNEL_ENCAP_IOAM6;
	lwt->flags |= LWTUNNEL_STATE_OUTPUT_REDIRECT;

	*ts = lwt;

	return 0;
}

static int ioam6_do_fill(struct net *net, struct sk_buff *skb)
{
	struct ioam6_trace_hdr *trace;
	struct ioam6_namespace *ns;

	trace = (struct ioam6_trace_hdr *)(skb_transport_header(skb)
					   + sizeof(struct ipv6_hopopt_hdr) + 2
					   + sizeof(struct ioam6_hdr));

	ns = ioam6_namespace(net, trace->namespace_id);
	if (ns)
		ioam6_fill_trace_data(skb, ns, trace, false);

	return 0;
}

static int ioam6_do_inline(struct net *net, struct sk_buff *skb,
			   struct ioam6_lwt_encap *tuninfo)
{
	struct ipv6hdr *oldhdr, *hdr;
	int hdrlen, err;

	hdrlen = (tuninfo->eh.hdrlen + 1) << 3;

	err = skb_cow_head(skb, hdrlen + skb->mac_len);
	if (unlikely(err))
		return err;

	oldhdr = ipv6_hdr(skb);
	skb_pull(skb, sizeof(*oldhdr));
	skb_postpull_rcsum(skb, skb_network_header(skb), sizeof(*oldhdr));

	skb_push(skb, sizeof(*oldhdr) + hdrlen);
	skb_reset_network_header(skb);
	skb_mac_header_rebuild(skb);

	hdr = ipv6_hdr(skb);
	memmove(hdr, oldhdr, sizeof(*oldhdr));
	tuninfo->eh.nexthdr = hdr->nexthdr;

	skb_set_transport_header(skb, sizeof(*hdr));
	skb_postpush_rcsum(skb, hdr, sizeof(*hdr) + hdrlen);

	memcpy(skb_transport_header(skb), (u8 *)tuninfo, hdrlen);

	hdr->nexthdr = NEXTHDR_HOP;
	hdr->payload_len = cpu_to_be16(skb->len - sizeof(*hdr));

	return ioam6_do_fill(net, skb);
}

static int ioam6_do_encap(struct net *net, struct sk_buff *skb,
			  struct ioam6_lwt_encap *tuninfo,
			  struct in6_addr *tundst)
{
	struct dst_entry *dst = skb_dst(skb);
	struct ipv6hdr *hdr, *inner_hdr;
	int hdrlen, len, err;

	hdrlen = (tuninfo->eh.hdrlen + 1) << 3;
	len = sizeof(*hdr) + hdrlen;

	err = skb_cow_head(skb, len + skb->mac_len);
	if (unlikely(err))
		return err;

	inner_hdr = ipv6_hdr(skb);

	skb_push(skb, len);
	skb_reset_network_header(skb);
	skb_mac_header_rebuild(skb);
	skb_set_transport_header(skb, sizeof(*hdr));

	tuninfo->eh.nexthdr = NEXTHDR_IPV6;
	memcpy(skb_transport_header(skb), (u8 *)tuninfo, hdrlen);

	hdr = ipv6_hdr(skb);
	memcpy(hdr, inner_hdr, sizeof(*hdr));

	hdr->nexthdr = NEXTHDR_HOP;
	hdr->payload_len = cpu_to_be16(skb->len - sizeof(*hdr));
	hdr->daddr = *tundst;
	ipv6_dev_get_saddr(net, dst->dev, &hdr->daddr,
			   IPV6_PREFER_SRC_PUBLIC, &hdr->saddr);

	skb_postpush_rcsum(skb, hdr, len);

	return ioam6_do_fill(net, skb);
}

static int ioam6_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct in6_addr orig_daddr;
	struct ioam6_lwt *ilwt;
	int err = -EINVAL;

	if (skb->protocol != htons(ETH_P_IPV6))
		goto drop;

	ilwt = ioam6_lwt_state(dst->lwtstate);
	orig_daddr = ipv6_hdr(skb)->daddr;

	switch (ilwt->mode) {
	case IOAM6_IPTUNNEL_MODE_INLINE:
do_inline:
		/* Direct insertion - if there is no Hop-by-Hop yet */
		if (ipv6_hdr(skb)->nexthdr == NEXTHDR_HOP)
			goto out;

		err = ioam6_do_inline(net, skb, &ilwt->tuninfo);
		if (unlikely(err))
			goto drop;

		break;
	case IOAM6_IPTUNNEL_MODE_ENCAP:
do_encap:
		/* Encapsulation (ip6ip6) */
		err = ioam6_do_encap(net, skb, &ilwt->tuninfo, &ilwt->tundst);
		if (unlikely(err))
			goto drop;

		break;
	case IOAM6_IPTUNNEL_MODE_AUTO:
		/* Automatic (RFC8200 compliant):
		 *  - local packets -> INLINE mode
		 *  - in-transit packets -> ENCAP mode
		 */
		if (!skb->dev)
			goto do_inline;

		goto do_encap;
	default:
		goto drop;
	}

	err = skb_cow_head(skb, LL_RESERVED_SPACE(dst->dev));
	if (unlikely(err))
		goto drop;

	if (!ipv6_addr_equal(&orig_daddr, &ipv6_hdr(skb)->daddr)) {
		preempt_disable();
		dst = dst_cache_get(&ilwt->cache);
		preempt_enable();

		if (unlikely(!dst)) {
			struct ipv6hdr *hdr = ipv6_hdr(skb);
			struct flowi6 fl6;

			memset(&fl6, 0, sizeof(fl6));
			fl6.daddr = hdr->daddr;
			fl6.saddr = hdr->saddr;
			fl6.flowlabel = ip6_flowinfo(hdr);
			fl6.flowi6_mark = skb->mark;
			fl6.flowi6_proto = hdr->nexthdr;

			dst = ip6_route_output(net, NULL, &fl6);
			if (dst->error) {
				err = dst->error;
				dst_release(dst);
				goto drop;
			}

			preempt_disable();
			dst_cache_set_ip6(&ilwt->cache, dst, &fl6.saddr);
			preempt_enable();
		}

		skb_dst_drop(skb);
		skb_dst_set(skb, dst);

		return dst_output(net, sk, skb);
	}
out:
	return dst->lwtstate->orig_output(net, sk, skb);
drop:
	kfree_skb(skb);
	return err;
}

static void ioam6_destroy_state(struct lwtunnel_state *lwt)
{
	dst_cache_destroy(&ioam6_lwt_state(lwt)->cache);
}

static int ioam6_fill_encap_info(struct sk_buff *skb,
				 struct lwtunnel_state *lwtstate)
{
	struct ioam6_lwt *ilwt = ioam6_lwt_state(lwtstate);
	int err;

	err = nla_put_u8(skb, IOAM6_IPTUNNEL_MODE, ilwt->mode);
	if (err)
		goto ret;

	if (ilwt->mode != IOAM6_IPTUNNEL_MODE_INLINE) {
		err = nla_put_in6_addr(skb, IOAM6_IPTUNNEL_DST, &ilwt->tundst);
		if (err)
			goto ret;
	}

	err = nla_put(skb, IOAM6_IPTUNNEL_TRACE, sizeof(ilwt->tuninfo.traceh),
		      &ilwt->tuninfo.traceh);
ret:
	return err;
}

static int ioam6_encap_nlsize(struct lwtunnel_state *lwtstate)
{
	struct ioam6_lwt *ilwt = ioam6_lwt_state(lwtstate);
	int nlsize;

	nlsize = nla_total_size(sizeof(ilwt->mode)) +
		  nla_total_size(sizeof(ilwt->tuninfo.traceh));

	if (ilwt->mode != IOAM6_IPTUNNEL_MODE_INLINE)
		nlsize += nla_total_size(sizeof(ilwt->tundst));

	return nlsize;
}

static int ioam6_encap_cmp(struct lwtunnel_state *a, struct lwtunnel_state *b)
{
	struct ioam6_trace_hdr *trace_a = ioam6_lwt_trace(a);
	struct ioam6_trace_hdr *trace_b = ioam6_lwt_trace(b);
	struct ioam6_lwt *ilwt_a = ioam6_lwt_state(a);
	struct ioam6_lwt *ilwt_b = ioam6_lwt_state(b);

	return (ilwt_a->mode != ilwt_b->mode ||
		(ilwt_a->mode != IOAM6_IPTUNNEL_MODE_INLINE &&
		 !ipv6_addr_equal(&ilwt_a->tundst, &ilwt_b->tundst)) ||
		trace_a->namespace_id != trace_b->namespace_id);
}

static const struct lwtunnel_encap_ops ioam6_iptun_ops = {
	.build_state		= ioam6_build_state,
	.destroy_state		= ioam6_destroy_state,
	.output		= ioam6_output,
	.fill_encap		= ioam6_fill_encap_info,
	.get_encap_size	= ioam6_encap_nlsize,
	.cmp_encap		= ioam6_encap_cmp,
	.owner			= THIS_MODULE,
};

int __init ioam6_iptunnel_init(void)
{
	return lwtunnel_encap_add_ops(&ioam6_iptun_ops, LWTUNNEL_ENCAP_IOAM6);
}

void ioam6_iptunnel_exit(void)
{
	lwtunnel_encap_del_ops(&ioam6_iptun_ops, LWTUNNEL_ENCAP_IOAM6);
}
