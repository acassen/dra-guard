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

#ifndef _DRA_DEBUG_H
#define _DRA_DEBUG_H

/* Hash table */
#define DEBUG_HASHTAB_BITS  15
#define DEBUG_HASHTAB_SIZE  (1 << DEBUG_HASHTAB_BITS)
#define DEBUG_HASHTAB_MASK  (DEBUG_HASHTAB_SIZE - 1)


/* Debug flags */
enum debug_flags {
	DRA_DEBUG_FL_MSISDN,
	DRA_DEBUG_FL_HASHED,
	DRA_DEBUG_FL_VTY,
	DRA_DEBUG_FL_JSON,
};

typedef struct _dra_debug_entry {
	uint64_t		msisdn;
	dra_mip6_agent_info_t	*mip;

	/* hash */
	struct hlist_node       hlist;

	unsigned long		flags;
	int			refcnt;
} dra_debug_entry_t;


/* Prototypes */
extern dra_debug_entry_t *dra_debug_entry_get(dra_htab_t *, uint64_t);
extern int dra_debug_entry_put(dra_debug_entry_t *);
extern dra_debug_entry_t *dra_debug_entry_alloc(dra_htab_t *, uint64_t);
extern int dra_debug_entry_destroy(dra_htab_t *, uint64_t);
extern int dra_debug_vty(vty_t *, dra_htab_t *);
extern int dra_debug_json(json_writer_t *, dra_htab_t *);
extern int dra_debug_disk_read_entries(dra_htab_t *, char *);
extern int dra_debug_disk_write_entries(dra_htab_t *, char *);
extern int dra_debug_init(dra_htab_t *);
extern int dra_debug_destroy(dra_htab_t *);

#endif
