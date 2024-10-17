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
#include <pcap/pcap.h>
#include <errno.h>

/* local includes */
#include "dra_guard.h"
#include "dra_pcap.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

static int mip_config_write(vty_t *vty);
cmd_node_t mip_node = {
        .node = MIP_NODE,
        .parent_node = CONFIG_NODE,
        .prompt = "%s(mip-home-agent-host)# ",
        .config_write = mip_config_write,
};


/*
 *	Command
 */
DEFUN(mip6_agent_info,
      mip6_agent_info_cmd,
      "mip6-agent-info WORD",
      "Configure MIP6 Agent Informations\n"
      "Context Name\n")
{
	dra_mip6_agent_info_t *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	new = dra_mip_get(argv[0]);
	if (!new)
		new = dra_mip_alloc(argv[0]);

	vty->node = MIP_NODE;
	vty->index = new;
	return CMD_SUCCESS;
}

DEFUN(no_mip6_agent_info,
      no_mip6_agent_info_cmd,
      "no mip6-agent-info WORD",
      "unconfigure MIP6 Agent Informations\n"
      "Context Name\n")
{
	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	dra_mip_release(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(destination_host,
      destination_host_cmd,
      "destination-host STRING",
      "Destination Host fqdn\n"
      "fqdn\n")
{
	dra_mip6_agent_info_t *mip = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	strlcpy(mip->destination_host, argv[0], MIP_DST_BUFSIZE);
	avp_build_mip6_agent_info(mip);
	__set_bit(MIP_FL_STATIC_HOST_BIT, &mip->flags);
	return CMD_SUCCESS;
}

DEFUN(destination_realm,
      destination_realm_cmd,
      "destination-realm STRING",
      "Destination realm fqdn\n"
      "fqdn\n")
{
	dra_mip6_agent_info_t *mip = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	strlcpy(mip->destination_realm, argv[0], MIP_DST_BUFSIZE);
	avp_build_mip6_agent_info(mip);
	__set_bit(MIP_FL_STATIC_REALM_BIT, &mip->flags);
	return CMD_SUCCESS;
}

DEFUN(destination_realm_dynamic,
      destination_realm_dynamic_cmd,
      "destination-realm-dynamic origin-realm",
      "Destination realm built from Origin-Realm\n")
{
	dra_mip6_agent_info_t *mip = vty->index;
	__set_bit(MIP_FL_DYNAMIC_REALM_ORIGIN_BIT, &mip->flags);
	return CMD_SUCCESS;
}

DEFUN(write_pcap,
      write_pcap_cmd,
      "write-pcap STRING",
      "Write matching pkt into file\n"
      "filename\n")
{
	dra_mip6_agent_info_t *mip = vty->index;
	dra_pcap_t *pcap;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (__test_bit(MIP_FL_WRITE_PCAP_BIT, &mip->flags)) {
		vty_out(vty, "%% write-pcap already configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	pcap = dra_pcap_alloc(argv[0]);
	if (!pcap) {
		vty_out(vty, "%% Error opening pcap file:%s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	mip->pcap = pcap;
	__set_bit(MIP_FL_WRITE_PCAP_BIT, &mip->flags);
	return CMD_SUCCESS;
}

DEFUN(no_write_pcap,
      no_write_pcap_cmd,
      "no write-pcap",
      "Write matching pkt into file\n"
      "filename\n")
{
	dra_mip6_agent_info_t *mip = vty->index;

	if (!__test_bit(MIP_FL_WRITE_PCAP_BIT, &mip->flags)) {
		vty_out(vty, "%% write-pcap not configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	dra_pcap_destroy(mip->pcap);
	mip->pcap = NULL;
	__clear_bit(MIP_FL_WRITE_PCAP_BIT, &mip->flags);
	return CMD_SUCCESS;
}

/* Configuration writer */
static int
mip_config_write(vty_t *vty)
{
	list_head_t *l = &daemon_data->mip_hosts;
	dra_mip6_agent_info_t *mip;
	dra_pcap_t *pcap;

	if (list_empty(l))
		return CMD_SUCCESS;

	list_for_each_entry(mip, l, next) {
		vty_out(vty, "mip6-agent-info %s%s", mip->name, VTY_NEWLINE);
		if (__test_bit(MIP_FL_STATIC_HOST_BIT, &mip->flags))
			vty_out(vty, " destination-host %s%s", mip->destination_host, VTY_NEWLINE);
		if (__test_bit(MIP_FL_STATIC_REALM_BIT, &mip->flags))
			vty_out(vty, " destination-realm %s%s", mip->destination_realm, VTY_NEWLINE);
		if (__test_bit(MIP_FL_DYNAMIC_REALM_ORIGIN_BIT, &mip->flags))
			vty_out(vty, " destination-realm-dynamic origin-realm%s", VTY_NEWLINE);
		if (__test_bit(MIP_FL_WRITE_PCAP_BIT, &mip->flags)) {
			pcap = mip->pcap;
			vty_out(vty, " write-pcap %s%s", pcap->filename, VTY_NEWLINE);
		}
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
dra_mip_vty_init(void)
{
	/* Install MIP commands. */
	install_node(&mip_node);
	install_element(CONFIG_NODE, &mip6_agent_info_cmd);
	install_element(CONFIG_NODE, &no_mip6_agent_info_cmd);

	install_default(MIP_NODE);
	install_element(MIP_NODE, &destination_host_cmd);
	install_element(MIP_NODE, &destination_realm_cmd);
	install_element(MIP_NODE, &destination_realm_dynamic_cmd);
	install_element(MIP_NODE, &write_pcap_cmd);
	install_element(MIP_NODE, &no_write_pcap_cmd);

	return 0;
}
