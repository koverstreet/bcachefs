/* SPDX-License-Identifier: GPL-2.0 */
/* Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#ifndef __MPTCP_PROTOCOL_H
#define __MPTCP_PROTOCOL_H

#include <linux/random.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>

#define MPTCP_SUPPORTED_VERSION	1

/* MPTCP option bits */
#define OPTION_MPTCP_MPC_SYN	BIT(0)
#define OPTION_MPTCP_MPC_SYNACK	BIT(1)
#define OPTION_MPTCP_MPC_ACK	BIT(2)
#define OPTION_MPTCP_MPJ_SYN	BIT(3)
#define OPTION_MPTCP_MPJ_SYNACK	BIT(4)
#define OPTION_MPTCP_MPJ_ACK	BIT(5)
#define OPTION_MPTCP_ADD_ADDR	BIT(6)
#define OPTION_MPTCP_ADD_ADDR6	BIT(7)
#define OPTION_MPTCP_RM_ADDR	BIT(8)

/* MPTCP option subtypes */
#define MPTCPOPT_MP_CAPABLE	0
#define MPTCPOPT_MP_JOIN	1
#define MPTCPOPT_DSS		2
#define MPTCPOPT_ADD_ADDR	3
#define MPTCPOPT_RM_ADDR	4
#define MPTCPOPT_MP_PRIO	5
#define MPTCPOPT_MP_FAIL	6
#define MPTCPOPT_MP_FASTCLOSE	7

/* MPTCP suboption lengths */
#define TCPOLEN_MPTCP_MPC_SYN		4
#define TCPOLEN_MPTCP_MPC_SYNACK	12
#define TCPOLEN_MPTCP_MPC_ACK		20
#define TCPOLEN_MPTCP_MPC_ACK_DATA	22
#define TCPOLEN_MPTCP_MPJ_SYN		12
#define TCPOLEN_MPTCP_MPJ_SYNACK	16
#define TCPOLEN_MPTCP_MPJ_ACK		24
#define TCPOLEN_MPTCP_DSS_BASE		4
#define TCPOLEN_MPTCP_DSS_ACK32		4
#define TCPOLEN_MPTCP_DSS_ACK64		8
#define TCPOLEN_MPTCP_DSS_MAP32		10
#define TCPOLEN_MPTCP_DSS_MAP64		14
#define TCPOLEN_MPTCP_DSS_CHECKSUM	2
#define TCPOLEN_MPTCP_ADD_ADDR		16
#define TCPOLEN_MPTCP_ADD_ADDR_PORT	18
#define TCPOLEN_MPTCP_ADD_ADDR_BASE	8
#define TCPOLEN_MPTCP_ADD_ADDR_BASE_PORT	10
#define TCPOLEN_MPTCP_ADD_ADDR6		28
#define TCPOLEN_MPTCP_ADD_ADDR6_PORT	30
#define TCPOLEN_MPTCP_ADD_ADDR6_BASE	20
#define TCPOLEN_MPTCP_ADD_ADDR6_BASE_PORT	22
#define TCPOLEN_MPTCP_PORT_LEN		2
#define TCPOLEN_MPTCP_RM_ADDR_BASE	4

/* MPTCP MP_JOIN flags */
#define MPTCPOPT_BACKUP		BIT(0)
#define MPTCPOPT_HMAC_LEN	20
#define MPTCPOPT_THMAC_LEN	8

/* MPTCP MP_CAPABLE flags */
#define MPTCP_VERSION_MASK	(0x0F)
#define MPTCP_CAP_CHECKSUM_REQD	BIT(7)
#define MPTCP_CAP_EXTENSIBILITY	BIT(6)
#define MPTCP_CAP_HMAC_SHA256	BIT(0)
#define MPTCP_CAP_FLAG_MASK	(0x3F)

/* MPTCP DSS flags */
#define MPTCP_DSS_DATA_FIN	BIT(4)
#define MPTCP_DSS_DSN64		BIT(3)
#define MPTCP_DSS_HAS_MAP	BIT(2)
#define MPTCP_DSS_ACK64		BIT(1)
#define MPTCP_DSS_HAS_ACK	BIT(0)
#define MPTCP_DSS_FLAG_MASK	(0x1F)

/* MPTCP ADD_ADDR flags */
#define MPTCP_ADDR_ECHO		BIT(0)
#define MPTCP_ADDR_IPVERSION_4	4
#define MPTCP_ADDR_IPVERSION_6	6

/* MPTCP socket flags */
#define MPTCP_DATA_READY	0
#define MPTCP_SEND_SPACE	1
#define MPTCP_WORK_RTX		2
#define MPTCP_WORK_EOF		3

struct mptcp_options_received {
	u64	sndr_key;
	u64	rcvr_key;
	u64	data_ack;
	u64	data_seq;
	u32	subflow_seq;
	u16	data_len;
	u16	mp_capable : 1,
		mp_join : 1,
		dss : 1,
		add_addr : 1,
		rm_addr : 1,
		family : 4,
		echo : 1,
		backup : 1;
	u32	token;
	u32	nonce;
	u64	thmac;
	u8	hmac[20];
	u8	join_id;
	u8	use_map:1,
		dsn64:1,
		data_fin:1,
		use_ack:1,
		ack64:1,
		mpc_map:1,
		__unused:2;
	u8	addr_id;
	u8	rm_id;
	union {
		struct in_addr	addr;
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
		struct in6_addr	addr6;
#endif
	};
	u64	ahmac;
	u16	port;
};

static inline __be32 mptcp_option(u8 subopt, u8 len, u8 nib, u8 field)
{
	return htonl((TCPOPT_MPTCP << 24) | (len << 16) | (subopt << 12) |
		     ((nib & 0xF) << 8) | field);
}

struct mptcp_addr_info {
	sa_family_t		family;
	__be16			port;
	u8			id;
	union {
		struct in_addr addr;
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
		struct in6_addr addr6;
#endif
	};
};

enum mptcp_pm_status {
	MPTCP_PM_ADD_ADDR_RECEIVED,
	MPTCP_PM_ESTABLISHED,
	MPTCP_PM_SUBFLOW_ESTABLISHED,
};

struct mptcp_pm_data {
	struct mptcp_addr_info local;
	struct mptcp_addr_info remote;

	spinlock_t	lock;		/*protects the whole PM data */

	bool		addr_signal;
	bool		server_side;
	bool		work_pending;
	bool		accept_addr;
	bool		accept_subflow;
	u8		add_addr_signaled;
	u8		add_addr_accepted;
	u8		local_addr_used;
	u8		subflows;
	u8		add_addr_signal_max;
	u8		add_addr_accept_max;
	u8		local_addr_max;
	u8		subflows_max;
	u8		status;

	struct		work_struct work;
};

struct mptcp_data_frag {
	struct list_head list;
	u64 data_seq;
	int data_len;
	int offset;
	int overhead;
	struct page *page;
};

/* MPTCP connection sock */
struct mptcp_sock {
	/* inet_connection_sock must be the first member */
	struct inet_connection_sock sk;
	u64		local_key;
	u64		remote_key;
	u64		write_seq;
	u64		ack_seq;
	atomic64_t	snd_una;
	unsigned long	timer_ival;
	u32		token;
	unsigned long	flags;
	bool		can_ack;
	spinlock_t	join_list_lock;
	struct work_struct work;
	struct list_head conn_list;
	struct list_head rtx_queue;
	struct list_head join_list;
	struct skb_ext	*cached_ext;	/* for the next sendmsg */
	struct socket	*subflow; /* outgoing connect/listener/!mp_capable */
	struct sock	*first;
	struct mptcp_pm_data	pm;
};

#define mptcp_for_each_subflow(__msk, __subflow)			\
	list_for_each_entry(__subflow, &((__msk)->conn_list), node)

static inline struct mptcp_sock *mptcp_sk(const struct sock *sk)
{
	return (struct mptcp_sock *)sk;
}

static inline struct mptcp_data_frag *mptcp_rtx_tail(const struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	if (list_empty(&msk->rtx_queue))
		return NULL;

	return list_last_entry(&msk->rtx_queue, struct mptcp_data_frag, list);
}

static inline struct mptcp_data_frag *mptcp_rtx_head(const struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	return list_first_entry_or_null(&msk->rtx_queue, struct mptcp_data_frag, list);
}

struct mptcp_subflow_request_sock {
	struct	tcp_request_sock sk;
	u16	mp_capable : 1,
		mp_join : 1,
		backup : 1;
	u8	local_id;
	u8	remote_id;
	u64	local_key;
	u64	idsn;
	u32	token;
	u32	ssn_offset;
	u64	thmac;
	u32	local_nonce;
	u32	remote_nonce;
	struct mptcp_sock	*msk;
};

static inline struct mptcp_subflow_request_sock *
mptcp_subflow_rsk(const struct request_sock *rsk)
{
	return (struct mptcp_subflow_request_sock *)rsk;
}

/* MPTCP subflow context */
struct mptcp_subflow_context {
	struct	list_head node;/* conn_list of subflows */
	u64	local_key;
	u64	remote_key;
	u64	idsn;
	u64	map_seq;
	u32	snd_isn;
	u32	token;
	u32	rel_write_seq;
	u32	map_subflow_seq;
	u32	ssn_offset;
	u32	map_data_len;
	u32	request_mptcp : 1,  /* send MP_CAPABLE */
		request_join : 1,   /* send MP_JOIN */
		request_bkup : 1,
		mp_capable : 1,	    /* remote is MPTCP capable */
		mp_join : 1,	    /* remote is JOINing */
		fully_established : 1,	    /* path validated */
		pm_notified : 1,    /* PM hook called for established status */
		conn_finished : 1,
		map_valid : 1,
		mpc_map : 1,
		backup : 1,
		data_avail : 1,
		rx_eof : 1,
		data_fin_tx_enable : 1,
		use_64bit_ack : 1, /* Set when we received a 64-bit DSN */
		can_ack : 1;	    /* only after processing the remote a key */
	u64	data_fin_tx_seq;
	u32	remote_nonce;
	u64	thmac;
	u32	local_nonce;
	u32	remote_token;
	u8	hmac[MPTCPOPT_HMAC_LEN];
	u8	local_id;
	u8	remote_id;

	struct	sock *tcp_sock;	    /* tcp sk backpointer */
	struct	sock *conn;	    /* parent mptcp_sock */
	const	struct inet_connection_sock_af_ops *icsk_af_ops;
	void	(*tcp_data_ready)(struct sock *sk);
	void	(*tcp_state_change)(struct sock *sk);
	void	(*tcp_write_space)(struct sock *sk);

	struct	rcu_head rcu;
};

static inline struct mptcp_subflow_context *
mptcp_subflow_ctx(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	/* Use RCU on icsk_ulp_data only for sock diag code */
	return (__force struct mptcp_subflow_context *)icsk->icsk_ulp_data;
}

static inline struct sock *
mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow)
{
	return subflow->tcp_sock;
}

static inline u64
mptcp_subflow_get_map_offset(const struct mptcp_subflow_context *subflow)
{
	return tcp_sk(mptcp_subflow_tcp_sock(subflow))->copied_seq -
		      subflow->ssn_offset -
		      subflow->map_subflow_seq;
}

static inline u64
mptcp_subflow_get_mapped_dsn(const struct mptcp_subflow_context *subflow)
{
	return subflow->map_seq + mptcp_subflow_get_map_offset(subflow);
}

int mptcp_is_enabled(struct net *net);
bool mptcp_subflow_data_available(struct sock *sk);
void mptcp_subflow_init(void);

/* called with sk socket lock held */
int __mptcp_subflow_connect(struct sock *sk, int ifindex,
			    const struct mptcp_addr_info *loc,
			    const struct mptcp_addr_info *remote);
int mptcp_subflow_create_socket(struct sock *sk, struct socket **new_sock);

static inline void mptcp_subflow_tcp_fallback(struct sock *sk,
					      struct mptcp_subflow_context *ctx)
{
	sk->sk_data_ready = ctx->tcp_data_ready;
	sk->sk_state_change = ctx->tcp_state_change;
	sk->sk_write_space = ctx->tcp_write_space;

	inet_csk(sk)->icsk_af_ops = ctx->icsk_af_ops;
}

extern const struct inet_connection_sock_af_ops ipv4_specific;
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
extern const struct inet_connection_sock_af_ops ipv6_specific;
#endif

void mptcp_proto_init(void);
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
int mptcp_proto_v6_init(void);
#endif

struct sock *mptcp_sk_clone(const struct sock *sk,
			    const struct mptcp_options_received *mp_opt,
			    struct request_sock *req);
void mptcp_get_options(const struct sk_buff *skb,
		       struct mptcp_options_received *mp_opt);

void mptcp_finish_connect(struct sock *sk);
void mptcp_data_ready(struct sock *sk, struct sock *ssk);
bool mptcp_finish_join(struct sock *sk);
void mptcp_data_acked(struct sock *sk);
void mptcp_subflow_eof(struct sock *sk);

int mptcp_token_new_request(struct request_sock *req);
void mptcp_token_destroy_request(u32 token);
int mptcp_token_new_connect(struct sock *sk);
int mptcp_token_new_accept(u32 token, struct sock *conn);
struct mptcp_sock *mptcp_token_get_sock(u32 token);
void mptcp_token_destroy(u32 token);

void mptcp_crypto_key_sha(u64 key, u32 *token, u64 *idsn);
static inline void mptcp_crypto_key_gen_sha(u64 *key, u32 *token, u64 *idsn)
{
	/* we might consider a faster version that computes the key as a
	 * hash of some information available in the MPTCP socket. Use
	 * random data at the moment, as it's probably the safest option
	 * in case multiple sockets are opened in different namespaces at
	 * the same time.
	 */
	get_random_bytes(key, sizeof(u64));
	mptcp_crypto_key_sha(*key, token, idsn);
}

void mptcp_crypto_hmac_sha(u64 key1, u64 key2, u8 *msg, int len, void *hmac);

void mptcp_pm_init(void);
void mptcp_pm_data_init(struct mptcp_sock *msk);
void mptcp_pm_close(struct mptcp_sock *msk);
void mptcp_pm_new_connection(struct mptcp_sock *msk, int server_side);
void mptcp_pm_fully_established(struct mptcp_sock *msk);
bool mptcp_pm_allow_new_subflow(struct mptcp_sock *msk);
void mptcp_pm_connection_closed(struct mptcp_sock *msk);
void mptcp_pm_subflow_established(struct mptcp_sock *msk,
				  struct mptcp_subflow_context *subflow);
void mptcp_pm_subflow_closed(struct mptcp_sock *msk, u8 id);
void mptcp_pm_add_addr_received(struct mptcp_sock *msk,
				const struct mptcp_addr_info *addr);

int mptcp_pm_announce_addr(struct mptcp_sock *msk,
			   const struct mptcp_addr_info *addr);
int mptcp_pm_remove_addr(struct mptcp_sock *msk, u8 local_id);
int mptcp_pm_remove_subflow(struct mptcp_sock *msk, u8 remote_id);

static inline bool mptcp_pm_should_signal(struct mptcp_sock *msk)
{
	return READ_ONCE(msk->pm.addr_signal);
}

static inline unsigned int mptcp_add_addr_len(int family)
{
	if (family == AF_INET)
		return TCPOLEN_MPTCP_ADD_ADDR;
	return TCPOLEN_MPTCP_ADD_ADDR6;
}

bool mptcp_pm_addr_signal(struct mptcp_sock *msk, unsigned int remaining,
			  struct mptcp_addr_info *saddr);
int mptcp_pm_get_local_id(struct mptcp_sock *msk, struct sock_common *skc);

void mptcp_pm_nl_init(void);
void mptcp_pm_nl_data_init(struct mptcp_sock *msk);
void mptcp_pm_nl_fully_established(struct mptcp_sock *msk);
void mptcp_pm_nl_subflow_established(struct mptcp_sock *msk);
void mptcp_pm_nl_add_addr_received(struct mptcp_sock *msk);
int mptcp_pm_nl_get_local_id(struct mptcp_sock *msk, struct sock_common *skc);

static inline struct mptcp_ext *mptcp_get_ext(struct sk_buff *skb)
{
	return (struct mptcp_ext *)skb_ext_find(skb, SKB_EXT_MPTCP);
}

static inline bool before64(__u64 seq1, __u64 seq2)
{
	return (__s64)(seq1 - seq2) < 0;
}

#define after64(seq2, seq1)	before64(seq1, seq2)

void mptcp_diag_subflow_init(struct tcp_ulp_ops *ops);

#endif /* __MPTCP_PROTOCOL_H */
