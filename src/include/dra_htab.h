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

#ifndef _DRA_HTAB_H
#define _DRA_HTAB_H

/* Distributed lock */
#define DLOCK_HASHTAB_BITS    10
#define DLOCK_HASHTAB_SIZE    (1 << DLOCK_HASHTAB_BITS)
#define DLOCK_HASHTAB_MASK    (DLOCK_HASHTAB_SIZE - 1)

typedef struct _dlock_mutex {
	pthread_mutex_t		mutex;
	uint32_t		refcnt;
} dlock_mutex_t;

/* htab */
typedef struct _dra_htab {
	struct hlist_head	*htab;
	dlock_mutex_t		*dlock;
} dra_htab_t;

/* Prototypes */
extern int dlock_lock_id(dlock_mutex_t *, uint32_t, uint32_t);
extern int dlock_unlock_id(dlock_mutex_t *, uint32_t, uint32_t);
extern dlock_mutex_t *dlock_init(void);
extern int dlock_destroy(dlock_mutex_t *);
extern void dra_htab_init(dra_htab_t *, size_t);
extern void dra_htab_destroy(dra_htab_t *);

#endif
