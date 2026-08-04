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
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

/* local includes */
#include "dra_guard.h"


/*
 *      Distributate lock handling
 */
static dlock_mutex_t *
dlock_hash(dlock_mutex_t *__array, uint32_t w1, uint32_t w2)
{
	return __array + (jhash_2words(w1, w2, 0) & DLOCK_HASHTAB_MASK);
}

int
dlock_lock_id(dlock_mutex_t *__array, uint32_t w1, uint32_t w2)
{
	pthread_mutex_lock(&dlock_hash(__array, w1, w2)->mutex);
	return 0;
}

int
dlock_unlock_id(dlock_mutex_t *__array, uint32_t w1, uint32_t w2)
{
	pthread_mutex_unlock(&dlock_hash(__array, w1, w2)->mutex);
	return 0;
}

/*
 * Walkers hold a whole bucket instead of a single id. An entry lands in
 * bucket jhash(id) & HTAB_MASK and locks jhash(id) & DLOCK_MASK, and the
 * dlock mask is a subset of the htab mask, so masking the bucket index
 * yields the very mutex every entry in it takes.
 */
int
dlock_lock_bucket(dlock_mutex_t *__array, uint32_t idx)
{
	pthread_mutex_lock(&__array[idx & DLOCK_HASHTAB_MASK].mutex);
	return 0;
}

int
dlock_unlock_bucket(dlock_mutex_t *__array, uint32_t idx)
{
	pthread_mutex_unlock(&__array[idx & DLOCK_HASHTAB_MASK].mutex);
	return 0;
}

dlock_mutex_t *
dlock_init(void)
{
	dlock_mutex_t *new;
	int i;

	new = (dlock_mutex_t *) MALLOC(DLOCK_HASHTAB_SIZE * sizeof(dlock_mutex_t));
	if (!new)
		return NULL;

	for (i = 0; i < DLOCK_HASHTAB_SIZE; i++)
		pthread_mutex_init(&new[i].mutex, NULL);

        return new;
}

int
dlock_destroy(dlock_mutex_t *__array)
{
	int i;

	for (i = 0; i < DLOCK_HASHTAB_SIZE; i++)
		pthread_mutex_destroy(&__array[i].mutex);

	FREE(__array);
	return 0;
}

/*
 *	HTAB handling
 */
void
dra_htab_init(dra_htab_t *h, size_t size)
{
	h->htab = (struct hlist_head *) MALLOC(sizeof(struct hlist_head) * size);
	h->dlock = dlock_init();
}

void
dra_htab_destroy(dra_htab_t *h)
{
	FREE(h->htab);
	FREE(h->dlock);
}
