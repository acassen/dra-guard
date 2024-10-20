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
 *	Debug entry hashtab
 */
static struct hlist_head *
dra_debug_entry_hashkey(dra_htab_t *h, uint64_t msisdn)
{
	return h->htab + (jhash_2words((uint32_t) msisdn, (uint32_t) (msisdn >> 32), 0) & DEBUG_HASHTAB_MASK);
}

static dra_debug_entry_t *
__dra_debug_entry_get(dra_htab_t *h, uint64_t msisdn)
{
	struct hlist_head *head = dra_debug_entry_hashkey(h, msisdn);
	struct hlist_node *n;
	dra_debug_entry_t *e;

	hlist_for_each_entry(e, n, head, hlist) {
		if (e->msisdn == msisdn) {
			__sync_add_and_fetch(&e->refcnt, 1);
			return e;
		}
	}

	return NULL;
}

dra_debug_entry_t *
dra_debug_entry_get(dra_htab_t *h, uint64_t msisdn)
{
	dra_debug_entry_t *e = NULL;

	dlock_lock_id(h->dlock, (uint32_t)msisdn, (uint32_t) (msisdn >> 32));
	e = __dra_debug_entry_get(h, msisdn);
	dlock_unlock_id(h->dlock, (uint32_t)msisdn, (uint32_t) (msisdn >> 32));

	return e;
}

int
dra_debug_entry_put(dra_debug_entry_t *e)
{
	if (__sync_sub_and_fetch(&e->refcnt, 1) == 0 && !__test_bit(DRA_DEBUG_FL_HASHED, &e->flags))
		FREE(e);
	return 0;
}

static int
__dra_debug_entry_hash(dra_htab_t *h, dra_debug_entry_t *e, uint64_t msisdn)
{
	struct hlist_head *head;

	if (__test_and_set_bit(DRA_DEBUG_FL_HASHED, &e->flags))
		return -1;

	head = dra_debug_entry_hashkey(h, msisdn);
	e->msisdn = msisdn;
	hlist_add_head(&e->hlist, head);
	__sync_add_and_fetch(&e->refcnt, 1);
	return 0;
}

static int
dra_debug_entry_hash(dra_htab_t *h, dra_debug_entry_t *e, uint64_t msisdn)
{
	dlock_lock_id(h->dlock, (uint32_t) msisdn, (uint32_t) (msisdn >> 32));
	__dra_debug_entry_hash(h, e, msisdn);
	dlock_unlock_id(h->dlock, (uint32_t) msisdn, (uint32_t) (msisdn >> 32));
	return 0;
}

static int
__dra_debug_entry_unhash(dra_htab_t *h, dra_debug_entry_t *e)
{
	if (!__test_and_clear_bit(DRA_DEBUG_FL_HASHED, &e->flags))
		return -1;

	hlist_del_init(&e->hlist);
	__sync_sub_and_fetch(&e->refcnt, 1);
	return 0;
}

static int
dra_debug_entry_unhash(dra_htab_t *h, dra_debug_entry_t *e)
{
	dlock_lock_id(h->dlock, (uint32_t) e->msisdn, (uint32_t) (e->msisdn >> 32));
	__dra_debug_entry_unhash(h, e);
	dlock_unlock_id(h->dlock, (uint32_t) e->msisdn, (uint32_t) (e->msisdn >> 32));
	return 0;
}

dra_debug_entry_t *
dra_debug_entry_alloc(dra_htab_t *h, uint64_t msisdn)
{
	dra_debug_entry_t *e;

	PMALLOC(e);
	dra_debug_entry_hash(h, e, msisdn);

	log_message(LOG_INFO, "%s(): allocating debug entry for msisdn:%ld"
			    , __FUNCTION__, msisdn);
	return e;
}

int
dra_debug_entry_destroy(dra_htab_t *h, uint64_t msisdn)
{
	dra_debug_entry_t *e;

	e = dra_debug_entry_get(h, msisdn);
	if (!e)
		return -1;

	dra_debug_entry_unhash(h, e);
	if (__sync_add_and_fetch(&e->refcnt, 0) == 0) {
		log_message(LOG_INFO, "%s(): releasing debug entry for msisdn:%ld"
				    , __FUNCTION__, msisdn);
		FREE(e);
	}
	return 0;
}

int
dra_debug_vty(vty_t *vty, dra_htab_t *h)
{
	struct hlist_node *n;
	dra_debug_entry_t *e;
	uint64_t i;

	for (i = 0; i < DEBUG_HASHTAB_SIZE; i++) {
		dlock_lock_id(h->dlock, (uint32_t) i, (uint32_t) (i >> 32));
		hlist_for_each_entry(e, n, &h->htab[i], hlist) {
			if (__test_bit(DRA_DEBUG_FL_VTY, &e->flags)) {
				vty_out(vty, " msisdn %ld mip6-agent-info %s%s"
					   , e->msisdn, e->mip->name, VTY_NEWLINE);
			}
		}
		dlock_unlock_id(h->dlock, (uint32_t) i, (uint32_t) (i >> 32));
	}

	return 0;
}

int
dra_debug_json(json_writer_t *jwriter, dra_htab_t *h)
{
	struct hlist_node *n;
	dra_debug_entry_t *e;
	uint64_t i;

	jsonw_name(jwriter, "target");
	jsonw_start_array(jwriter);
	for (i = 0; i < DEBUG_HASHTAB_SIZE; i++) {
		dlock_lock_id(h->dlock, (uint32_t) i, (uint32_t) (i >> 32));
		hlist_for_each_entry(e, n, &h->htab[i], hlist) {
			if (__test_bit(DRA_DEBUG_FL_JSON, &e->flags)) {
				jsonw_start_object(jwriter);
				jsonw_name(jwriter, "msisdn");
				jsonw_printf_enquote(jwriter, "%ld", e->msisdn);
				jsonw_name(jwriter, "profile");
				jsonw_printf_enquote(jwriter, "%s", e->mip->name);
				jsonw_end_object(jwriter);
			}
		}
		dlock_unlock_id(h->dlock, (uint32_t) i, (uint32_t) (i >> 32));
	}
	jsonw_end_array(jwriter);

	return 0;
}

int
dra_debug_disk_read_entries(dra_htab_t *h, char *path)
{
	dra_debug_entry_t *e;
	dra_mip6_agent_info_t *mip;
	uint64_t msisdn;
	char profile[MIP_NAME_MAX_LEN];
	int fd, nbytes;

	fd = dra_disk_open_read(path);
	if (fd < 0) {
		log_message(LOG_INFO, "%s(): Error opening file %s (%m)"
				    , __FUNCTION__
				    , path);
		return -1;
	}

	for (;;) {
		nbytes = dra_disk_read(fd, (char *) &msisdn, sizeof(uint64_t));
		if (nbytes <= 0)
			break;

		nbytes = dra_disk_read(fd, profile, MIP_NAME_MAX_LEN);
		if (nbytes <= 0)
			break;

		mip = dra_mip_get(profile);
		if (!mip) {
			log_message(LOG_INFO, "%s(): unknown mip6-agent-info:'%s'"
					    , __FUNCTION__
					    , profile);
			continue;
		}

		e = dra_debug_entry_get(&daemon_data->debug_target, msisdn);
		if (!e)
			e = dra_debug_entry_alloc(h, msisdn);
		e->mip = mip;
		__set_bit(DRA_DEBUG_FL_JSON, &e->flags);
		dra_debug_entry_put(e);
	}

	close(fd);
	return 0;
}

int
dra_debug_disk_write_entries(dra_htab_t *h, char *path)
{
	struct hlist_node *n;
	dra_debug_entry_t *e;
	uint64_t i;
	int fd;

	fd = dra_disk_open_write(path);
	if (fd < 0) {
		log_message(LOG_INFO, "%s(): Error opening file %s (%m)"
				    , __FUNCTION__
				    , path);
		return -1;
	}

	for (i = 0; i < DEBUG_HASHTAB_SIZE; i++) {
		dlock_lock_id(h->dlock, (uint32_t) i, (uint32_t) (i >> 32));
		hlist_for_each_entry(e, n, &h->htab[i], hlist) {
			if (__test_bit(DRA_DEBUG_FL_JSON, &e->flags)) {
				dra_disk_write(fd, (char *) &e->msisdn, sizeof(uint64_t));
				dra_disk_write(fd, e->mip->name, MIP_NAME_MAX_LEN);
			}
		}
		dlock_unlock_id(h->dlock, (uint32_t) i, (uint32_t) (i >> 32));
	}

	close(fd);
	return 0;
}

int
dra_debug_init(dra_htab_t *h)
{
	dra_htab_init(h, DEBUG_HASHTAB_SIZE);
	return 0;
}

int
dra_debug_destroy(dra_htab_t *h)
{
	struct hlist_node *n, *n2;
	dra_debug_entry_t *e;
	uint64_t i;

	for (i = 0; i < DEBUG_HASHTAB_SIZE; i++) {
		dlock_lock_id(h->dlock, (uint32_t) i, (uint32_t) (i >> 32));
		hlist_for_each_entry_safe(e, n, n2, &h->htab[i], hlist) {
			__dra_debug_entry_unhash(h, e);
			FREE(e);
		}
		dlock_unlock_id(h->dlock, (uint32_t) i, (uint32_t) (i >> 32));
	}

	dra_htab_destroy(h);
	return 0;
}
