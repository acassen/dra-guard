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
#include <unistd.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <pcap/pcap.h>
#include <errno.h>

/* local includes */
#include "dra_guard.h"
#include "dra_pcap.h"

/* Local data */
pthread_mutex_t dra_mip_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Extern data */
extern data_t *daemon_data;


/*
 *	MIP Utilities
 */
dra_mip6_agent_info_t *
dra_mip_get(const char *name)
{
	list_head_t *l = &daemon_data->mip_hosts;
	dra_mip6_agent_info_t *mip;

	pthread_mutex_lock(&dra_mip_mutex);
	list_for_each_entry(mip, l, next) {
		if (!strncmp(name, mip->name, DRA_NAME_MAX_LEN)) {
			pthread_mutex_unlock(&dra_mip_mutex);
			return mip;
		}
	}
	pthread_mutex_unlock(&dra_mip_mutex);

	return NULL;
}

static int
dra_mip_add(dra_mip6_agent_info_t *mip)
{
	pthread_mutex_lock(&dra_mip_mutex);
	list_add_tail(&mip->next, &daemon_data->mip_hosts);
	pthread_mutex_unlock(&dra_mip_mutex);
	return 0;
}

static int
__dra_mip_del(dra_mip6_agent_info_t *mip)
{
	list_head_del(&mip->next);
	return 0;
}


/*
 *	ARP Service init
 */
dra_mip6_agent_info_t *
dra_mip_alloc(const char *name)
{
	dra_mip6_agent_info_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	strlcpy(new->name, name, MIP_NAME_MAX_LEN);

	dra_mip_add(new);
	return new;
}

static int
__dra_mip_release(dra_mip6_agent_info_t *mip)
{
	__dra_mip_del(mip);
	dra_pcap_destroy(mip->pcap);
	FREE(mip);
	return 0;
}

int
dra_mip_release(const char *name)
{
	dra_mip6_agent_info_t *mip;

	mip = dra_mip_get(name);
	if (!mip)
		return -1;

	pthread_mutex_lock(&dra_mip_mutex);
	__dra_mip_release(mip);
	pthread_mutex_unlock(&dra_mip_mutex);
	return 0;
}

int
dra_mip_destroy(void)
{
	dra_mip6_agent_info_t *mip, *_mip;

	pthread_mutex_lock(&dra_mip_mutex);
	list_for_each_entry_safe(mip, _mip, &daemon_data->mip_hosts, next)
		__dra_mip_release(mip);
	pthread_mutex_unlock(&dra_mip_mutex);

	return 0;
}
