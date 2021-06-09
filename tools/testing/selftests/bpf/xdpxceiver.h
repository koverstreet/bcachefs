/* SPDX-License-Identifier: GPL-2.0
 * Copyright(c) 2020 Intel Corporation.
 */

#ifndef XDPXCEIVER_H_
#define XDPXCEIVER_H_

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define MAX_INTERFACES 2
#define MAX_INTERFACE_NAME_CHARS 7
#define MAX_INTERFACES_NAMESPACE_CHARS 10
#define MAX_SOCKS 1
#define MAX_TEARDOWN_ITER 10
#define MAX_BIDI_ITER 2
#define PKT_HDR_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + \
			sizeof(struct udphdr))
#define MIN_PKT_SIZE 64
#define ETH_FCS_SIZE 4
#define PKT_SIZE (MIN_PKT_SIZE - ETH_FCS_SIZE)
#define IP_PKT_SIZE (PKT_SIZE - sizeof(struct ethhdr))
#define IP_PKT_VER 0x4
#define IP_PKT_TOS 0x9
#define UDP_PKT_SIZE (IP_PKT_SIZE - sizeof(struct iphdr))
#define UDP_PKT_DATA_SIZE (UDP_PKT_SIZE - sizeof(struct udphdr))
#define TMOUT_SEC (3)
#define EOT (-1)
#define USLEEP_MAX 200000
#define THREAD_STACK 60000000
#define SOCK_RECONF_CTR 10
#define BATCH_SIZE 64
#define POLL_TMOUT 1000
#define NEED_WAKEUP true

typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

enum TESTS {
	ORDER_CONTENT_VALIDATE_XDP_SKB = 0,
	ORDER_CONTENT_VALIDATE_XDP_DRV = 1,
};

u8 uut;
u8 debug_pkt_dump;
u32 num_frames;
u8 switching_notify;
u8 bidi_pass;

static u32 opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static int opt_queue;
static int opt_pkt_count;
static int opt_poll;
static int opt_teardown;
static int opt_bidi;
static u32 opt_xdp_bind_flags = XDP_USE_NEED_WAKEUP;
static u8 pkt_data[XSK_UMEM__DEFAULT_FRAME_SIZE];
static u32 pkt_counter;
static u32 prev_pkt = -1;
static int sigvar;

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
	unsigned long rx_npkts;
	unsigned long tx_npkts;
	unsigned long prev_rx_npkts;
	unsigned long prev_tx_npkts;
	u32 outstanding_tx;
};

struct flow_vector {
	enum fvector {
		tx,
		rx,
	} vector;
};

struct generic_data {
	u32 seqnum;
};

struct ifaceconfigobj {
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	struct in_addr dst_ip;
	struct in_addr src_ip;
	u16 src_port;
	u16 dst_port;
} *ifaceconfig;

struct ifobject {
	int ifindex;
	int ifdict_index;
	char ifname[MAX_INTERFACE_NAME_CHARS];
	char nsname[MAX_INTERFACES_NAMESPACE_CHARS];
	struct flow_vector fv;
	struct xsk_socket_info *xsk;
	struct xsk_umem_info *umem;
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	u32 dst_ip;
	u32 src_ip;
	u16 src_port;
	u16 dst_port;
};

static struct ifobject *ifdict[MAX_INTERFACES];

/*threads*/
atomic_int spinning_tx;
atomic_int spinning_rx;
pthread_mutex_t sync_mutex;
pthread_mutex_t sync_mutex_tx;
pthread_cond_t signal_rx_condition;
pthread_cond_t signal_tx_condition;
pthread_t t0, t1, ns_thread;
pthread_attr_t attr;

struct targs {
	bool retptr;
	int idx;
};

TAILQ_HEAD(head_s, pkt) head = TAILQ_HEAD_INITIALIZER(head);
struct head_s *head_p;
struct pkt {
	char *pkt_frame;

	TAILQ_ENTRY(pkt) pkt_nodes;
} *pkt_node_rx, *pkt_node_rx_q;

struct pkt_frame {
	char *payload;
} *pkt_obj;

struct pkt_frame **pkt_buf;

#endif				/* XDPXCEIVER_H */
