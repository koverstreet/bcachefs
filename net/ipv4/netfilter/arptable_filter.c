// SPDX-License-Identifier: GPL-2.0-only
/*
 * Filtering ARP tables module.
 *
 * Copyright (C) 2002 David S. Miller (davem@redhat.com)
 *
 */

#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_arp/arp_tables.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("David S. Miller <davem@redhat.com>");
MODULE_DESCRIPTION("arptables filter table");

#define FILTER_VALID_HOOKS ((1 << NF_ARP_IN) | (1 << NF_ARP_OUT) | \
			   (1 << NF_ARP_FORWARD))

static const struct xt_table packet_filter = {
	.name		= "filter",
	.valid_hooks	= FILTER_VALID_HOOKS,
	.me		= THIS_MODULE,
	.af		= NFPROTO_ARP,
	.priority	= NF_IP_PRI_FILTER,
};

static struct nf_hook_ops *arpfilter_ops __read_mostly;

static int arptable_filter_table_init(struct net *net)
{
	struct arpt_replace *repl;
	int err;

	repl = arpt_alloc_initial_table(&packet_filter);
	if (repl == NULL)
		return -ENOMEM;
	err = arpt_register_table(net, &packet_filter, repl, arpfilter_ops);
	kfree(repl);
	return err;
}

static void __net_exit arptable_filter_net_pre_exit(struct net *net)
{
	arpt_unregister_table_pre_exit(net, "filter");
}

static void __net_exit arptable_filter_net_exit(struct net *net)
{
	arpt_unregister_table(net, "filter");
}

static struct pernet_operations arptable_filter_net_ops = {
	.exit = arptable_filter_net_exit,
	.pre_exit = arptable_filter_net_pre_exit,
};

static int __init arptable_filter_init(void)
{
	int ret = xt_register_template(&packet_filter,
				       arptable_filter_table_init);

	if (ret < 0)
		return ret;

	arpfilter_ops = xt_hook_ops_alloc(&packet_filter, arpt_do_table);
	if (IS_ERR(arpfilter_ops)) {
		xt_unregister_template(&packet_filter);
		return PTR_ERR(arpfilter_ops);
	}

	ret = register_pernet_subsys(&arptable_filter_net_ops);
	if (ret < 0) {
		xt_unregister_template(&packet_filter);
		kfree(arpfilter_ops);
		return ret;
	}

	return ret;
}

static void __exit arptable_filter_fini(void)
{
	unregister_pernet_subsys(&arptable_filter_net_ops);
	xt_unregister_template(&packet_filter);
	kfree(arpfilter_ops);
}

module_init(arptable_filter_init);
module_exit(arptable_filter_fini);
