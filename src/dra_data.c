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

/* local includes */
#include "dra_guard.h"


/* Extern data */
extern data_t *daemon_data;


/*
 *	Daemon Control Block helpers
 */
data_t *
alloc_daemon_data(void)
{
	data_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->bpf_progs);
	INIT_LIST_HEAD(&new->arp_ip_nat_rules);
	INIT_LIST_HEAD(&new->ip_nat_rules);
	INIT_LIST_HEAD(&new->sctp_ip_nat_rules);
	INIT_LIST_HEAD(&new->arp_listeners);
	INIT_LIST_HEAD(&new->mip_hosts);
	INIT_LIST_HEAD(&new->sctp_proxys);
	INIT_LIST_HEAD(&new->plugins);
	dra_debug_init(&new->debug_target);

	return new;
}

void
free_daemon_data(void)
{
	dra_json_destroy();
	dra_sctp_destroy();
	dra_mip_destroy();
	dra_arp_destroy();
	dra_bpf_destroy();
	dra_nat_destroy();
	dra_plugin_destroy();
	dra_debug_destroy(&daemon_data->debug_target);
	FREE(daemon_data);
}

