/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of dra-guard is to provide robust and secure
 *              extensions to DRA feature (Diameter Routing Agent). DRA are
 *              used in mobile networks to route Diameter traffic between
 *              mobile network equipments, like at Roaming interconnections.
 *              DRA-Guard implements a set of features to manipulate and
 *              analyze Diameter payloads via a Plugin framework and a
 *              built-in Route-Optimization feature.
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

static int debug_profile_config_write(vty_t *vty);
cmd_node_t debug_profile_node = {
        .node = DEBUG_PROFILE_NODE,
        .parent_node = CONFIG_NODE,
        .prompt = "%s(debug)# ",
        .config_write = debug_profile_config_write,
};


/*
 *	Command
 */
DEFUN(debug_profile,
      debug_profile_cmd,
      "debug-profile",
      "Configure Debug options\n")
{
	vty->node = DEBUG_PROFILE_NODE;
	return CMD_SUCCESS;
}

DEFUN(msisdn,
      msisdn_cmd,
      "msisdn INTEGER mip6-agent-info STRING",
      "MSISDN\n"
      "number\n"
      "MIP6 Agent Info to use\n"
      "string\n")
{
	dra_debug_entry_t *e;
	dra_mip6_agent_info_t *mip;
	uint64_t msisdn;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	mip = dra_mip_get(argv[1]);
	if (!mip) {
		vty_out(vty, "%% unknown mip6-agent-info:'%s'%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	msisdn = strtoul(argv[0], NULL, 10);

	e = dra_debug_entry_get(&daemon_data->debug_target, msisdn);
	if (!e)
		e = dra_debug_entry_alloc(&daemon_data->debug_target, msisdn);
	e->mip = mip;
	__set_bit(DRA_DEBUG_FL_VTY, &e->flags);
	dra_debug_entry_put(e);
	return CMD_SUCCESS;
}

DEFUN(no_msisdn,
      no_msisdn_cmd,
      "no msisdn INTEGER",
      "MSISDN\n"
      "number\n")
{
	uint64_t msisdn;
	int err;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	msisdn = strtoul(argv[0], NULL, 10);
	err = dra_debug_entry_destroy(&daemon_data->debug_target, msisdn);
	if (err) {
		vty_out(vty, "%% unknown msisdn %ld%s", msisdn, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

/* Configuration writer */
static int
debug_profile_config_write(vty_t *vty)
{
	vty_out(vty, "debug-profile%s", VTY_NEWLINE);
	dra_debug_vty(vty, &daemon_data->debug_target);
	vty_out(vty, "!%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
dra_debug_vty_init(void)
{
	/* Install DEBUG commands. */
	install_node(&debug_profile_node);
	install_element(CONFIG_NODE, &debug_profile_cmd);

	install_default(DEBUG_PROFILE_NODE);
	install_element(DEBUG_PROFILE_NODE, &msisdn_cmd);
	install_element(DEBUG_PROFILE_NODE, &no_msisdn_cmd);

	return 0;
}
