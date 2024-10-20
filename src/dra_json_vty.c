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

static int json_config_write(vty_t *vty);
cmd_node_t json_node = {
        .node = JSON_NODE,
        .parent_node = CONFIG_NODE,
        .prompt = "%s(json)# ",
        .config_write = json_config_write,
};


/*
 *	Command
 */
DEFUN(json,
      json_cmd,
      "json",
      "Configure JSON channel\n")
{
	vty->node = JSON_NODE;
	return CMD_SUCCESS;
}

DEFUN(json_listen,
      json_listen_cmd,
//    "listen (A.B.C.D|X:X:X:X) port <1024-65535>",
      "listen STRING port INTEGER",
      "DRA-Guard JSON request channel\n"
      "IPv4 Address\n"
      "IPv6 Address\n"
      "listening TCP Port\n"
      "Number\n")
{
	dra_json_channel_t *srv = &daemon_data->json_channel;
	struct sockaddr_storage *addr = &srv->addr;
	int port = 0, err = 0;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("TCP Port", port, argv[1], 1024, 65535);

	err = inet_stosockaddr(argv[0], port, addr);
	if (err) {
		vty_out(vty, "%% malformed IP address %s%s", argv[0], VTY_NEWLINE);
		memset(addr, 0, sizeof(struct sockaddr_storage));
		return CMD_WARNING;
	}

	srv->thread_cnt = DRA_JSON_THREAD_CNT_DEFAULT;
	dra_json_init();
	dra_json_worker_start();
	return CMD_SUCCESS;
}

DEFUN(json_store,
      json_store_cmd,
      "store STRING",
      "Save JSON entries\n"
      "PATH to file\n")
{
	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	strlcpy(daemon_data->json_store, argv[0], DRA_STR_MAX_LEN);
	dra_debug_disk_read_entries(&daemon_data->debug_target, daemon_data->json_store);
	__set_bit(DRA_FL_JSON_STORE_BIT, &daemon_data->flags);
	return CMD_SUCCESS;
}

/* Configuration writer */
static int
json_config_write(vty_t *vty)
{
	dra_json_channel_t *srv = &daemon_data->json_channel;

	if (!__test_bit(DRA_JSON_FL_RUNNING, &srv->flags))
		return CMD_SUCCESS;

	vty_out(vty, "json%s", VTY_NEWLINE);
	vty_out(vty, " listen %s port %d%s"
		   , inet_sockaddrtos(&srv->addr)
		   , ntohs(inet_sockaddrport(&srv->addr))
		   , VTY_NEWLINE);
	if (__test_bit(DRA_FL_JSON_STORE_BIT, &daemon_data->flags))
		vty_out(vty, " store %s%s", daemon_data->json_store, VTY_NEWLINE);
	vty_out(vty, "!%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
dra_json_vty_init(void)
{
	/* Install DEBUG commands. */
	install_node(&json_node);
	install_element(CONFIG_NODE, &json_cmd);

	install_default(JSON_NODE);
	install_element(JSON_NODE, &json_listen_cmd);
	install_element(JSON_NODE, &json_store_cmd);

	return 0;
}
