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

static int arp_config_write(vty_t *vty);
cmd_node_t arp_node = {
        .node = ARP_NODE,
        .parent_node = CONFIG_NODE,
        .prompt = "%s(arp-reply)# ",
        .config_write = arp_config_write,
};


/*
 *	Command
 */
DEFUN(arp_reply,
      arp_reply_cmd,
      "arp-reply",
      "Configure ARP reply\n")
{
	vty->node = ARP_NODE;
	return CMD_SUCCESS;
}

static int
arp_interface_parse(vty_t *vty, const char **argv, int *ifindex, uint32_t *ip_address)
{
	int ret;

	*ifindex = if_nametoindex(argv[0]);
	if (!*ifindex) {
		vty_out(vty, "%% Error resolving interface %s (%m)%s"
			   , argv[3]
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = inet_ston(argv[1], ip_address);
	if (!ret) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	return 0;
}

DEFUN(arp_interface,
      arp_interface_cmd,
      "interface STRING ip-address A.B.C.D",
      "Set Global PDN nameserver\n"
      "IPv4 Address\n")
{
	dra_arp_t *arp;
	uint32_t ip_address;
	int err, ifindex;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = arp_interface_parse(vty, argv, &ifindex, &ip_address);
	if (err)
		return CMD_WARNING;

	arp = dra_arp_init(ifindex, argv[0], ip_address);
	if (!arp) {
		vty_out(vty, "%% arp-reply already configured on %s for %u.%u.%u.%u%s"
			   , argv[0], NIPQUAD(ip_address), VTY_NEWLINE);
		return CMD_WARNING;
	}

	dra_arp_start(arp);

	return CMD_SUCCESS;
}

DEFUN(no_arp_interface,
      no_arp_interface_cmd,
      "no interface STRING ip-address A.B.C.D",
      "Set Global PDN nameserver\n"
      "IPv4 Address\n")
{
	uint32_t ip_address;
	int err, ifindex;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = arp_interface_parse(vty, argv, &ifindex, &ip_address);
	if (err)
		return CMD_WARNING;

	err = dra_arp_release(ifindex, ip_address);
	if (err)
		vty_out(vty, "%% no arp-reply configured on interface %s for %u.%u.%u.%u%s"
			   , argv[0], NIPQUAD(ip_address), VTY_NEWLINE);
	return CMD_SUCCESS;
}

/* Configuration writer */
static int
arp_config_write(vty_t *vty)
{
	list_head_t *l = &daemon_data->arp_listeners;

	dra_arp_t *arp;

	if (list_empty(l))
		return CMD_SUCCESS;

	vty_out(vty, "arp-reply%s", VTY_NEWLINE);
	list_for_each_entry(arp, l, next) {
		vty_out(vty, " interface %s ip-address %u.%u.%u.%u%s"
			   , arp->ifname, NIPQUAD(arp->ip_address)
			   , VTY_NEWLINE);
	}
	vty_out(vty, "!%s", VTY_NEWLINE);


	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
dra_arp_vty_init(void)
{

	/* Install PDN commands. */
	install_node(&arp_node);
	install_element(CONFIG_NODE, &arp_reply_cmd);

	install_default(ARP_NODE);
	install_element(ARP_NODE, &arp_interface_cmd);
	install_element(ARP_NODE, &no_arp_interface_cmd);

	/* Install show commands */
//	install_element(VIEW_NODE, &show_xdp_forwarding_cmd);


	return 0;
}
