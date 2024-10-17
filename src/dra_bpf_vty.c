/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of dra-guard is to provide robust and secure
 *              extensions to DRA feature (Diameter Routing Agent). DRA are
 *              used in mobile networks in order to redirect users terminals
 *              to their HPLMN in Roaming situations. DRA-Guard implements a
 *              set of features to manipulate and analyze Diameter payloads
 *              via a Plugin framework and a built-in Route-Optimization
 *              feature.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2024 Alexandre Cassen, <acassen@gmail.com>
 */

/* system includes */
#include <pthread.h>
#include <sys/stat.h>
#include <net/if.h>
#include <errno.h>

/* local includes */
#include "dra_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

static int bpf_config_write(vty_t *vty);
cmd_node_t bpf_node = {
        .node = BPF_NODE,
        .parent_node = CONFIG_NODE,
        .prompt = "%s(bpf)# ",
        .config_write = bpf_config_write,
};


/*
 *	Command
 */
DEFUN(bpf,
      bpf_cmd,
      "bpf",
      "Configure BPF progs\n")
{
	vty->node = BPF_NODE;
	return CMD_SUCCESS;
}

DEFUN(bpf_qdisc_clsact,
      bpf_qdisc_clsact_cmd,
      "qdisc-clsact STRING object-file STRING interface STRING [progname STRING]",
      "Qdisc Classifier-Action\n"
      "label\n"
      "BPF object file\n"
      "PATH to BPF prog\n"
      "interface to attach to\n"
      "interface name\n"
      "BPF Program Name\n"
      "Name\n")
{
	list_head_t *l = &daemon_data->bpf_progs;
	dra_bpf_opts_t *opts;
	int err;

	if (dra_bpf_opts_exist(l, argc, argv)) {
		vty_out(vty, "%% Qdisc BPF program already loaded on interface %s!!!%s"
			   , argv[1]
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	opts = dra_bpf_opts_alloc(BPF_PROG_QDISC, dra_qdisc_clast_unload);
	err = dra_bpf_opts_load(opts, vty, argc, argv, dra_qdisc_clsact_load);
	if (err) {
		FREE(opts);
		return CMD_WARNING;
	}

	dra_bpf_opts_add(opts, l);
	return CMD_SUCCESS;
}

DEFUN(bpf_qdisc_clsact_arp_nat,
      bpf_qdisc_clsact_arp_nat_cmd,
      "qdisc-clsact STRING arp-request ip nat A.B.C.D A.B.C.D A.B.C.D",
      "Qdisc Classifier-Action\n"
      "label\n"
      "IPv4\n"
      "Network Address Translation\n"
      "IPv4 Address\n"
      "IPv4 Address\n"
      "Netmask\n")
{
	return dra_bpf_arp_ip_nat_insert(vty, argc, argv);
}

DEFUN(bpf_qdisc_clsact_nat,
      bpf_qdisc_clsact_nat_cmd,
      "qdisc-clsact STRING ip-src-dst nat A.B.C.D A.B.C.D A.B.C.D",
      "Qdisc Classifier-Action\n"
      "label\n"
      "IPv4\n"
      "Network Address Translation\n"
      "IPv4 Address\n"
      "IPv4 Address\n"
      "Netmask\n")
{
	return dra_bpf_ip_nat_insert(vty, DRA_IP_NAT_SRC_DST, argc, argv);
}

DEFUN(bpf_qdisc_clsact_src_nat,
      bpf_qdisc_clsact_src_nat_cmd,
      "qdisc-clsact STRING ip-src nat A.B.C.D A.B.C.D A.B.C.D",
      "Qdisc Classifier-Action\n"
      "label\n"
      "IPv4\n"
      "Network Address Translation\n"
      "IPv4 Address\n"
      "IPv4 Address\n"
      "Netmask\n")
{
	return dra_bpf_ip_nat_insert(vty, DRA_IP_NAT_SRC, argc, argv);
}

DEFUN(bpf_qdisc_clsact_dst_nat,
      bpf_qdisc_clsact_dst_nat_cmd,
      "qdisc-clsact STRING ip-dst nat A.B.C.D A.B.C.D A.B.C.D",
      "Qdisc Classifier-Action\n"
      "label\n"
      "IPv4\n"
      "Network Address Translation\n"
      "IPv4 Address\n"
      "IPv4 Address\n"
      "Netmask\n")
{
	return dra_bpf_ip_nat_insert(vty, DRA_IP_NAT_DST, argc, argv);
}

DEFUN(bpf_qdisc_clsact_sctp_nat,
      bpf_qdisc_clsact_sctp_nat_cmd,
      "qdisc-clsact STRING sctp ip nat A.B.C.D A.B.C.D A.B.C.D",
      "Qdisc Classifier-Action\n"
      "label\n"
      "IPv4\n"
      "Network Address Translation\n"
      "IPv4 Address\n"
      "IPv4 Address\n"
      "Netmask\n")
{
	return dra_bpf_sctp_ip_nat_insert(vty, argc, argv);
}

DEFUN(no_bpf_qdisc_clsact,
      no_bpf_qdisc_clsact_cmd,
      "no qdisc-clsact STRING object-file STRING interface STRING",
      "Qdisc Classifier-Action\n"
      "label\n"
      "BPF object file\n"
      "PATH to BPF prog\n"
      "interface to attach to\n"
      "interface name\n")
{
	list_head_t *l = &daemon_data->bpf_progs;
	dra_bpf_opts_t *opts;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	opts = dra_bpf_opts_exist(l, argc, argv);
	if (!opts) {
		vty_out(vty, "%% unknown Qdisc BPF program %s on interface %s !!!%s"
			   , argv[0], argv[1]
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	dra_bpf_opts_del(opts);
	return CMD_SUCCESS;
}

DEFUN(bpf_xdp,
      bpf_xdp_cmd,
      "xdp STRING object-file STRING interface STRING [progname STRING]",
      "XDP\n"
      "label\n"
      "BPF object file\n"
      "PATH to BPF prog\n"
      "interface to attach to\n"
      "interface name\n"
      "BPF Program Name\n"
      "Name\n")
{
	list_head_t *l = &daemon_data->bpf_progs;
	dra_bpf_opts_t *opts;
	int err;

	if (dra_bpf_opts_exist(l, argc, argv)) {
		vty_out(vty, "%% XDP BPF program already loaded on interface %s!!!%s"
			   , argv[1]
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	opts = dra_bpf_opts_alloc(BPF_PROG_XDP, dra_xdp_unload);
	err = dra_bpf_opts_load(opts, vty, argc, argv, dra_xdp_load);
	if (err) {
		FREE(opts);
		return CMD_WARNING;
	}

	dra_bpf_opts_add(opts, l);
	return CMD_SUCCESS;
}

DEFUN(bpf_xdp_arp_nat,
      bpf_xdp_arp_nat_cmd,
      "xdp STRING arp-reply ip nat A.B.C.D A.B.C.D A.B.C.D",
      "XDP\n"
      "label\n"
      "IPv4\n"
      "Network Address Translation\n"
      "IPv4 Address\n"
      "IPv4 Address\n"
      "Netmask\n")
{
	return dra_bpf_arp_ip_nat_insert(vty, argc, argv);
}

DEFUN(bpf_xdp_nat,
      bpf_xdp_nat_cmd,
      "xdp STRING ip-src-dst nat A.B.C.D A.B.C.D A.B.C.D",
      "XDP\n"
      "label\n"
      "IPv4\n"
      "Network Address Translation\n"
      "IPv4 Address\n"
      "IPv4 Address\n"
      "Netmask\n")
{
	return dra_bpf_ip_nat_insert(vty, DRA_IP_NAT_SRC_DST, argc, argv);
}

DEFUN(bpf_xdp_src_nat,
      bpf_xdp_src_nat_cmd,
      "xdp STRING ip-src nat A.B.C.D A.B.C.D A.B.C.D",
      "XDP\n"
      "label\n"
      "IPv4\n"
      "Network Address Translation\n"
      "IPv4 Address\n"
      "IPv4 Address\n"
      "Netmask\n")
{
	return dra_bpf_ip_nat_insert(vty, DRA_IP_NAT_SRC, argc, argv);
}

DEFUN(bpf_xdp_dst_nat,
      bpf_xdp_dst_nat_cmd,
      "xdp STRING ip-dst nat A.B.C.D A.B.C.D A.B.C.D",
      "XDP\n"
      "label\n"
      "IPv4\n"
      "Network Address Translation\n"
      "IPv4 Address\n"
      "IPv4 Address\n"
      "Netmask\n")
{
	return dra_bpf_ip_nat_insert(vty, DRA_IP_NAT_DST, argc, argv);
}

DEFUN(bpf_xdp_sctp_nat,
      bpf_xdp_sctp_nat_cmd,
      "xdp STRING sctp ip nat A.B.C.D A.B.C.D A.B.C.D",
      "XDP\n"
      "label\n"
      "IPv4\n"
      "Network Address Translation\n"
      "IPv4 Address\n"
      "IPv4 Address\n"
      "Netmask\n")
{
	return dra_bpf_sctp_ip_nat_insert(vty, argc, argv);
}

DEFUN(no_bpf_xdp,
      no_bpf_xdp_cmd,
      "no xdp STRING object-file STRING interface STRING",
      "XDP\n"
      "label\n"
      "BPF object file\n"
      "PATH to BPF prog\n"
      "interface to attach to\n"
      "interface name\n")
{
	list_head_t *l = &daemon_data->bpf_progs;
	dra_bpf_opts_t *opts;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	opts = dra_bpf_opts_exist(l, argc, argv);
	if (!opts) {
		vty_out(vty, "%% unknown XDP BPF program %s on interface %s !!!%s"
			   , argv[0], argv[1]
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	dra_bpf_opts_del(opts);
	return CMD_SUCCESS;
}


/* Configuration writer */
static const char *dra_bpf_ip_nat_cmd_name[] = {
	"qdisc-clsact",
	"xdp"
};
static int
dra_bpf_opts_config_write(vty_t *vty, dra_bpf_opts_t *opts)
{
	char ifname[IF_NAMESIZE];

	if (opts->progname[0]) {
		vty_out(vty, " %s object-file %s interface %s progname %s%s"
			   , dra_bpf_ip_nat_cmd_name[opts->type]
			   , opts->filename
			   , if_indextoname(opts->ifindex, ifname)
			   , opts->progname
			   , VTY_NEWLINE);
		return 0;
	}

	vty_out(vty, " %s object-file %s interface %s%s"
		   , dra_bpf_ip_nat_cmd_name[opts->type]
		   , opts->filename
		   , if_indextoname(opts->ifindex, ifname)
		   , VTY_NEWLINE);
	return 0;
}

static int
dra_bpf_arp_ip_nat_config_write(vty_t *vty, dra_nat_rule_t *rule)
{
	dra_bpf_opts_t *opts = rule->opts;
	const char *arp_op = "arp-request";

	if (opts->type == BPF_PROG_XDP)
		arp_op = "arp-reply";

	vty_out(vty, " %s %s %s ip nat %u.%u.%u.%u %u.%u.%u.%u %u.%u.%u.%u%s"
		   , dra_bpf_ip_nat_cmd_name[opts->type]
		   , opts->label
		   , arp_op
		   , NIPQUAD(rule->key)
		   , NIPQUAD(rule->addr)
		   , NIPQUAD(rule->netmask)
		   , VTY_NEWLINE);
	return 0;
}

static int
dra_bpf_ip_nat_config_write(vty_t *vty, dra_nat_rule_t *rule)
{
	dra_bpf_opts_t *opts = rule->opts;
	const char *type = "ip-src-dst";

	if (rule->type == DRA_IP_NAT_SRC)
		type = "ip-src";
	if (rule->type == DRA_IP_NAT_DST)
		type = "ip-dst";

	vty_out(vty, " %s %s %s nat %u.%u.%u.%u %u.%u.%u.%u %u.%u.%u.%u%s"
		   , dra_bpf_ip_nat_cmd_name[opts->type]
		   , opts->label
		   , type
		   , NIPQUAD(rule->key)
		   , NIPQUAD(rule->addr)
		   , NIPQUAD(rule->netmask)
		   , VTY_NEWLINE);
	return 0;
}

static int
dra_bpf_sctp_ip_nat_config_write(vty_t *vty, dra_nat_rule_t *rule)
{
	dra_bpf_opts_t *opts = rule->opts;

	vty_out(vty, " %s %s sctp ip nat %u.%u.%u.%u %u.%u.%u.%u %u.%u.%u.%u%s"
		   , dra_bpf_ip_nat_cmd_name[opts->type]
		   , opts->label
		   , NIPQUAD(rule->key)
		   , NIPQUAD(rule->addr)
		   , NIPQUAD(rule->netmask)
		   , VTY_NEWLINE);
	return 0;
}

static int
bpf_config_write(vty_t *vty)
{
	dra_bpf_opts_t *opts;
	dra_nat_rule_t *r;

	if (list_empty(&daemon_data->bpf_progs))
		return CMD_SUCCESS;

	vty_out(vty, "bpf%s", VTY_NEWLINE);
	list_for_each_entry(opts, &daemon_data->bpf_progs, next)
		dra_bpf_opts_config_write(vty, opts);
	list_for_each_entry(r, &daemon_data->sctp_ip_nat_rules, next)
		dra_bpf_arp_ip_nat_config_write(vty, r);
	list_for_each_entry(r, &daemon_data->ip_nat_rules, next)
		dra_bpf_ip_nat_config_write(vty, r);
	list_for_each_entry(r, &daemon_data->sctp_ip_nat_rules, next)
		dra_bpf_sctp_ip_nat_config_write(vty, r);
	vty_out(vty, "!%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
dra_bpf_vty_init(void)
{

	/* Install PDN commands. */
	install_node(&bpf_node);
	install_element(CONFIG_NODE, &bpf_cmd);

	install_default(BPF_NODE);
	install_element(BPF_NODE, &bpf_qdisc_clsact_cmd);
	install_element(BPF_NODE, &bpf_qdisc_clsact_arp_nat_cmd);
	install_element(BPF_NODE, &bpf_qdisc_clsact_nat_cmd);
	install_element(BPF_NODE, &bpf_qdisc_clsact_src_nat_cmd);
	install_element(BPF_NODE, &bpf_qdisc_clsact_dst_nat_cmd);
	install_element(BPF_NODE, &bpf_qdisc_clsact_sctp_nat_cmd);
	install_element(BPF_NODE, &no_bpf_qdisc_clsact_cmd);
	install_element(BPF_NODE, &bpf_xdp_cmd);
	install_element(BPF_NODE, &bpf_xdp_arp_nat_cmd);
	install_element(BPF_NODE, &bpf_xdp_nat_cmd);
	install_element(BPF_NODE, &bpf_xdp_src_nat_cmd);
	install_element(BPF_NODE, &bpf_xdp_dst_nat_cmd);
	install_element(BPF_NODE, &bpf_xdp_sctp_nat_cmd);
	install_element(BPF_NODE, &no_bpf_xdp_cmd);

	return 0;
}
