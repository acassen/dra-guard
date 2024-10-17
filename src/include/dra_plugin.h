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

#ifndef _DRA_PLUGIN_H
#define _DRA_PLUGIN_H

/* Plugin Actions */
#define DRA_PLUGIN_ACT_PASS	0
#define DRA_PLUGIN_ACT_DROP	1

/* Plugin Hooks */
#define DRA_PLUGIN_INGRESS_READ_HOOK	0
#define DRA_PLUGIN_EGRESS_READ_HOOK	1

#define DRA_PLUGIN_NAME_MAX_LEN		64
#define DRA_PLUGIN_PATH_MAX_LEN		128
#define DRA_PLUGIN_ARGS_MAX_LEN		512

/* MIP related */
typedef struct _dra_plugin {
	char		name[DRA_PLUGIN_NAME_MAX_LEN];
	char		path[DRA_PLUGIN_PATH_MAX_LEN];
	char		args[DRA_PLUGIN_ARGS_MAX_LEN];
	void		*hdl;
	/* callback functions */
	int		(*generic_pkt) (pkt_buffer_t *);
	int		(*ingress_pkt_read) (pkt_buffer_t *);
	int		(*egress_pkt_read) (pkt_buffer_t *);
	int		(*init) (const char **, int);
	int		(*destroy) (void);

	int		refcnt;
	list_head_t	next;
} dra_plugin_t;

/* inline stuff */
static inline void __dra_plugin_ref(dra_plugin_t *p)
{
	__sync_add_and_fetch(&p->refcnt, 1);
}

static inline void __dra_plugin_unref(dra_plugin_t *p)
{
	__sync_sub_and_fetch(&p->refcnt, 1);
}


/* Prototypes */
extern dra_plugin_t *dra_plugin_get(const char *);
extern int dra_plugin_put(dra_plugin_t *);
extern int dra_plugin_load(dra_plugin_t *, const char **, int);
extern int dra_plugin_argscpy(dra_plugin_t *plugin, const char *argv[], int argc);
extern dra_plugin_t *dra_plugin_alloc(const char *);
extern int dra_plugin_release(dra_plugin_t *);
extern int dra_plugin_destroy(void);

#endif
