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

#ifndef _DRA_DATA_H
#define _DRA_DATA_H

/* Default values */
#define DRA_STR_MAX_LEN		128
#define DRA_PATH_MAX_LEN	128
#define DRA_NAME_MAX_LEN	64

/* Flags */
enum daemon_flags {
	DRA_FL_STOP_BIT,
	DRA_FL_JSON_STORE_BIT,
};

/* Main control block */
typedef struct _data {
	list_head_t		bpf_progs;
	list_head_t		arp_ip_nat_rules;
	list_head_t		ip_nat_rules;
	list_head_t		sctp_ip_nat_rules;
	list_head_t		arp_listeners;
	list_head_t		mip_hosts;
	list_head_t		sctp_proxys;
	list_head_t		plugins;
	dra_htab_t		debug_target;
	dra_json_channel_t	json_channel;
	char			json_store[DRA_STR_MAX_LEN];

	unsigned long		flags;
} data_t;

/* Prototypes */
extern data_t *alloc_daemon_data(void);
extern void free_daemon_data(void);

#endif
