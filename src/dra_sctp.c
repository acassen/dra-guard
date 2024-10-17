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
#include <unistd.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <errno.h>

/* local includes */
#include "dra_guard.h"

/* Extern data */
extern data_t *daemon_data;

/*
 *	SCTP Proxy plugin related
 */

int
dra_sctp_proxy_plugin_get(dra_sctp_plugin_t *p)
{
	__sync_add_and_fetch(&p->refcnt, 1);
	return 0;
}

int
dra_sctp_proxy_plugin_put(dra_sctp_plugin_t *p)
{
	if (__sync_sub_and_fetch(&p->refcnt, 1) == 0 &&
	    __test_bit(SCTP_FL_PLUGIN_UNLOAD, &p->flags)) {
		dra_plugin_put(p->plugin);
		p->plugin = NULL;
		p->flags = 0;
	}

	return 0;
}


int
dra_sctp_proxy_plugin_add(dra_sctp_proxy_t *p, dra_plugin_t *plugin)
{
	int i;

	for (i = 0; i < DRA_SCTP_MAX_PLUGIN; i++) {
		if (p->plugin[i].plugin)
			continue;

		p->plugin[i].plugin = plugin;
		__sync_add_and_fetch(&p->plugin_cnt, 1);
		__set_bit(SCTP_FL_PLUGIN_LOADED, &p->flags);
		return 0;
	}

	return -1;
}

int
dra_sctp_proxy_plugin_del(dra_sctp_proxy_t *p, const char *name)
{
	int i;

	if (!__test_bit(SCTP_FL_PLUGIN_LOADED, &p->flags))
		return -1;

	for (i = 0; i < DRA_SCTP_MAX_PLUGIN; i++) {
		if (!p->plugin[i].plugin)
			continue;

		if (!strncmp(p->plugin[i].plugin->name, name, DRA_NAME_MAX_LEN)) {
			if (__sync_sub_and_fetch(&p->plugin_cnt, 1) == 0)
				__clear_bit(SCTP_FL_PLUGIN_LOADED, &p->flags);
			
			__set_bit(SCTP_FL_PLUGIN_UNLOAD, &p->plugin[i].flags);
			if (__sync_add_and_fetch(&p->plugin[i].refcnt, 0) == 0) {
				dra_plugin_put(p->plugin[i].plugin);
				p->plugin[i].plugin = NULL;
				p->plugin[i].flags = 0;
			}
			return 0;
		}
	}

	return -1;
}


/*
 	SCTP Proxy init
 */
static int
dra_sctp_parse_addrs_list(char *addr_list, char *port, struct sockaddr **addrs)
{
	struct addrinfo hints, *res;
	char *addr, *tmp;
	int addrs_cnt = 1;

	if (!addr_list || !port)
		return -1;

	for (tmp = (char *)addr_list; *tmp != '\0'; tmp++) {
		if (*tmp == ',') {
			addrs_cnt++;
		}
	}

	*addrs = (struct sockaddr *) MALLOC(sizeof(struct sockaddr_in) * addrs_cnt);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_SCTP;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

	tmp = (char *)*addrs;
	for (addr = strtok((char *)addr_list, ","); addr != NULL; addr = strtok(NULL, ",")) {
		if (getaddrinfo(addr, port, &hints, &res) != 0) {
			FREE(*addrs);
			return -1;
		}

		memcpy(tmp, res->ai_addr, res->ai_addrlen);
		tmp += res->ai_addrlen;
		freeaddrinfo(res);
	}

	return addrs_cnt;
}

int
dra_sctp_parse_addrs_list_port(char *addr_list, struct sockaddr **addrs)
{
	char *port, *last_colon;

	if (!addr_list)
		return -1;

	last_colon = strrchr(addr_list, ':');
	if (!last_colon)
		return -1;
	
	port = last_colon + 1;
	*last_colon = '\0';
	return dra_sctp_parse_addrs_list(addr_list, port, addrs);
}




dra_sctp_proxy_t *
dra_sctp_proxy_get(const char *name)
{
	dra_sctp_proxy_t *p;
	size_t len = strlen(name);

	list_for_each_entry(p, &daemon_data->sctp_proxys, next) {
		if (!strncmp(p->name, name, len))
			return p;
	}

	return NULL;
}

dra_sctp_proxy_t *
dra_sctp_proxy_alloc(const char *name)
{
	dra_sctp_proxy_t *new;

	PMALLOC(new);
        INIT_LIST_HEAD(&new->next);
        strlcpy(new->name, name, DRA_NAME_MAX_LEN);
	new->thread_cnt = SCTP_LISTENER_THREAD_CNT_DEFAULT;
	pthread_mutex_init(&new->workers_mutex, NULL);
	pthread_mutex_init(&new->assocs_mutex, NULL);
        list_add_tail(&new->next, &daemon_data->sctp_proxys);

	return new;
}

int
dra_sctp_proxy_init(dra_sctp_proxy_t *l)
{
	dra_sctp_proto_init(l);
	return 0;
}

int
dra_sctp_proxy_destroy(dra_sctp_proxy_t *l)
{
	dra_sctp_proto_destroy(l);
	list_head_del(&l->next);
	FREE(l);
	return 0;
}

static int
dra_sctp_proxys_destroy(void)
{
	dra_sctp_proxy_t *p, *_p;

	list_for_each_entry_safe(p, _p, &daemon_data->sctp_proxys, next)
		dra_sctp_proxy_destroy(p);

	return 0;
}


/*
 *	SCTP related
 */
int
dra_sctp_destroy(void)
{
	dra_sctp_proxys_destroy();
	return 0;
}
