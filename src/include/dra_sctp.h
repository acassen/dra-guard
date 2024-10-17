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

#ifndef _DRA_SCTP_H
#define _DRA_SCTP_H

/* Default values */
#define SCTP_LISTENER_THREAD_CNT_DEFAULT	5
#define SCTP_PKT_BUFFER_SIZE			(1 << 13)

/* SCTP Channel definition */
#define DRA_SCTP_TIMEOUT	(1 * TIMER_HZ)
#define DRA_SCTP_LISTENER_TIMER	(1 * TIMER_HZ)
#define DRA_SCTP_TIMER		(1 * TIMER_HZ)
#define DRA_SCTP_MAX_PLUGIN	10

/* SCTP session flags */
enum assoc_flags {
	SCTP_FL_CONNECTED = 0,
	SCTP_FL_INGRESS,
	SCTP_FL_EGRESS,
	SCTP_FL_STOP,
	SCTP_FL_RUNNING,
	SCTP_FL_COMPLETE,
	SCTP_FL_DISCARD,
	SCTP_FL_LOCAL_NAT,
	SCTP_FL_REWRITE_ULA,
	SCTP_FL_MATCH_TARGET_REWRITE_ULA,
	SCTP_FL_PLUGIN_LOADED,
	SCTP_FL_PLUGIN_UNLOAD,
};

/* SCTP channel */
typedef struct _dra_sctp_worker {
	int			id;
	pthread_t		task;
	int			fd;
	struct _dra_sctp_proxy	*proxy;		/* backpointer */

	/* I/O MUX related */
	thread_master_t		*master;
	thread_ref_t		r_thread;

	/* Diameter related */
	avp_ctx_t		*avp_ctx;

	list_head_t		next;

	unsigned long		flags;
} dra_sctp_worker_t;

typedef struct _dra_sctp_plugin {
	dra_plugin_t		*plugin;
	int			refcnt;

	unsigned long		flags;
} dra_sctp_plugin_t;

typedef struct _dra_sctp_proxy {
	char			name[DRA_NAME_MAX_LEN];

	/* Server conf */
	struct sockaddr		*addrs;
	char			addrs_str[DRA_STR_MAX_LEN];
	int			addrs_cnt;
	struct sctp_initmsg	server_initmsg;
	int			thread_cnt;

	/* Client conf */
	struct sockaddr		*connect_addrs;
	char			connect_addrs_str[DRA_STR_MAX_LEN];
	int			connect_addrs_cnt;
	struct sctp_initmsg	client_initmsg;
	uint32_t		local_nat_netmask;
	uint32_t		local_nat_ip_match;
	uint32_t		local_nat_ip;

	pthread_mutex_t		workers_mutex;
	list_head_t		workers;

	pthread_mutex_t		assocs_mutex;
	list_head_t		assocs;

	dra_sctp_plugin_t	plugin[DRA_SCTP_MAX_PLUGIN];
	int			plugin_cnt;

	list_head_t		next;

	unsigned long		flags;
} dra_sctp_proxy_t;

typedef struct _dra_sctp_peer {
	int                     fd;
	pkt_buffer_t		*pkt;
	struct sctp_initmsg	initmsg;
	struct sctp_sndrcvinfo	sinfo;

	/* I/O MUX related */
	thread_ref_t		w_thread;
	thread_ref_t		r_thread;

	unsigned long		flags;
} dra_sctp_peer_t;

typedef struct _dra_sctp_assoc {
	struct sockaddr		*addrs;
	char			addrs_str[DRA_STR_MAX_LEN];
	int			addrs_cnt;
	dra_sctp_peer_t		ingress;
	dra_sctp_peer_t		egress;
	
	dra_sctp_worker_t	*worker;	/* backpointer */

	list_head_t		next;

	unsigned long		flags;
} dra_sctp_assoc_t;


/* Prototypes */
extern int dra_sctp_proxy_plugin_get(dra_sctp_plugin_t *);
extern int dra_sctp_proxy_plugin_put(dra_sctp_plugin_t *);
extern int dra_sctp_proxy_plugin_add(dra_sctp_proxy_t *, dra_plugin_t *);
extern int dra_sctp_proxy_plugin_del(dra_sctp_proxy_t *, const char *);
extern int sctp_assoc_str(struct sockaddr *, int, char *, size_t);
extern int dra_sctp_parse_addrs_list_port(char *, struct sockaddr **);
extern dra_sctp_proxy_t *dra_sctp_proxy_get(const char *);
extern dra_sctp_proxy_t *dra_sctp_proxy_alloc(const char *name);
extern int dra_sctp_listener_destroy(dra_sctp_proxy_t *);
extern int dra_sctp_destroy(void);


#endif
