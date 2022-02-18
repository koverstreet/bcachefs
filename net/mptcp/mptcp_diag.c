// SPDX-License-Identifier: GPL-2.0
/* MPTCP socket monitoring support
 *
 * Copyright (c) 2020 Red Hat
 *
 * Author: Paolo Abeni <pabeni@redhat.com>
 */

#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/inet_diag.h>
#include <net/netlink.h>
#include <uapi/linux/mptcp.h>
#include "protocol.h"

static int sk_diag_dump(struct sock *sk, struct sk_buff *skb,
			struct netlink_callback *cb,
			const struct inet_diag_req_v2 *req,
			struct nlattr *bc, bool net_admin)
{
	if (!inet_diag_bc_sk(bc, sk))
		return 0;

	return inet_sk_diag_fill(sk, inet_csk(sk), skb, cb, req, NLM_F_MULTI,
				 net_admin);
}

static int mptcp_diag_dump_one(struct netlink_callback *cb,
			       const struct inet_diag_req_v2 *req)
{
	struct sk_buff *in_skb = cb->skb;
	struct mptcp_sock *msk = NULL;
	struct sk_buff *rep;
	int err = -ENOENT;
	struct net *net;
	struct sock *sk;

	net = sock_net(in_skb->sk);
	msk = mptcp_token_get_sock(net, req->id.idiag_cookie[0]);
	if (!msk)
		goto out_nosk;

	err = -ENOMEM;
	sk = (struct sock *)msk;
	rep = nlmsg_new(nla_total_size(sizeof(struct inet_diag_msg)) +
			inet_diag_msg_attrs_size() +
			nla_total_size(sizeof(struct mptcp_info)) +
			nla_total_size(sizeof(struct inet_diag_meminfo)) + 64,
			GFP_KERNEL);
	if (!rep)
		goto out;

	err = inet_sk_diag_fill(sk, inet_csk(sk), rep, cb, req, 0,
				netlink_net_capable(in_skb, CAP_NET_ADMIN));
	if (err < 0) {
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(rep);
		goto out;
	}
	err = nlmsg_unicast(net->diag_nlsk, rep, NETLINK_CB(in_skb).portid);

out:
	sock_put(sk);

out_nosk:
	return err;
}

static void mptcp_diag_dump(struct sk_buff *skb, struct netlink_callback *cb,
			    const struct inet_diag_req_v2 *r)
{
	bool net_admin = netlink_net_capable(cb->skb, CAP_NET_ADMIN);
	struct net *net = sock_net(skb->sk);
	struct inet_diag_dump_data *cb_data;
	struct mptcp_sock *msk;
	struct nlattr *bc;

	cb_data = cb->data;
	bc = cb_data->inet_diag_nla_bc;

	while ((msk = mptcp_token_iter_next(net, &cb->args[0], &cb->args[1])) !=
	       NULL) {
		struct inet_sock *inet = (struct inet_sock *)msk;
		struct sock *sk = (struct sock *)msk;
		int ret = 0;

		if (!(r->idiag_states & (1 << sk->sk_state)))
			goto next;
		if (r->sdiag_family != AF_UNSPEC &&
		    sk->sk_family != r->sdiag_family)
			goto next;
		if (r->id.idiag_sport != inet->inet_sport &&
		    r->id.idiag_sport)
			goto next;
		if (r->id.idiag_dport != inet->inet_dport &&
		    r->id.idiag_dport)
			goto next;

		ret = sk_diag_dump(sk, skb, cb, r, bc, net_admin);
next:
		sock_put(sk);
		if (ret < 0) {
			/* will retry on the same position */
			cb->args[1]--;
			break;
		}
		cond_resched();
	}
}

static void mptcp_diag_get_info(struct sock *sk, struct inet_diag_msg *r,
				void *_info)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct mptcp_info *info = _info;

	r->idiag_rqueue = sk_rmem_alloc_get(sk);
	r->idiag_wqueue = sk_wmem_alloc_get(sk);
	if (!info)
		return;

	mptcp_diag_fill_info(msk, info);
}

static const struct inet_diag_handler mptcp_diag_handler = {
	.dump		 = mptcp_diag_dump,
	.dump_one	 = mptcp_diag_dump_one,
	.idiag_get_info  = mptcp_diag_get_info,
	.idiag_type	 = IPPROTO_MPTCP,
	.idiag_info_size = sizeof(struct mptcp_info),
};

static int __init mptcp_diag_init(void)
{
	return inet_diag_register(&mptcp_diag_handler);
}

static void __exit mptcp_diag_exit(void)
{
	inet_diag_unregister(&mptcp_diag_handler);
}

module_init(mptcp_diag_init);
module_exit(mptcp_diag_exit);
MODULE_LICENSE("GPL");
MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_NETLINK, NETLINK_SOCK_DIAG, 2-262 /* AF_INET - IPPROTO_MPTCP */);
