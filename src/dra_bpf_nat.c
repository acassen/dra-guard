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
#include <errno.h>
#include <libbpf.h>

/* local includes */
#include "dra_guard.h"

/* Extern data */
extern data_t *daemon_data;


/*
 *	BPF related
 */
static struct ip_nat_rule *
dra_bpf_nat_rule_alloc(size_t *sz)
{
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct ip_nat_rule *new;

	new = calloc(nr_cpus, sizeof(*new));
	if (!new)
		return NULL;

	*sz = nr_cpus * sizeof(struct ip_nat_rule);
	return new;
}

static int
dra_bpf_nat_rule_set(struct ip_nat_rule *r, dra_nat_rule_t *r_nat)
{
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	int i;

	for (i = 0; i < nr_cpus; i++) {
		r[i].type = r_nat->type;
		r[i].addr = r_nat->addr;
		r[i].netmask = r_nat->netmask;
	}

	return 0;
}

static int
dra_bpf_nat_add(struct bpf_map *map, dra_nat_rule_t *rule)
{
	struct ip_nat_rule *new = NULL;
	char errmsg[DRA_XDP_STRERR_BUFSIZE];
	int err = 0;
	size_t sz;

	new = dra_bpf_nat_rule_alloc(&sz);
	if (!new) {
		log_message(LOG_INFO, "%s(): Cant allocate dra_nat_rule !!!", __FUNCTION__);
		err = -1;
		goto end;
	}

	dra_bpf_nat_rule_set(new, rule);
	err = bpf_map__update_elem(map, &rule->key, sizeof(uint32_t), new, sz, BPF_NOEXIST);
	if (err) {
		libbpf_strerror(err, errmsg, DRA_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant add BPF NAT rule for IP:%u.%u.%u.%u (%s)"
				    , __FUNCTION__
				    , NIPQUAD(rule->key)
				    , errmsg);
		err = -1;
	}

  end:
	if (new)
		free(new);
	return err;
}


/*
 *	NAT Utilities
 */
static int
dra_nat_rule_alloc(dra_bpf_opts_t *opts, int type, int map_idx, uint32_t key, uint32_t addr, uint32_t netmask)
{
	struct bpf_map *map = opts->bpf_maps[map_idx].map;
	dra_nat_rule_t *new;
	int err;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	new->type = type;
	new->key = key;
	new->addr = addr;
	new->netmask = netmask;
	new->opts = opts;

	err = dra_bpf_nat_add(map, new);
	if (err) {
		log_message(LOG_INFO, "%s(): Error setting BPF NAT rule for %s"
				    , __FUNCTION__
				    , opts->label);
		FREE(new);
		return -1;
	}

	if (map_idx == DRA_BPF_MAP_IP_NAT)
		list_add_tail(&new->next, &daemon_data->ip_nat_rules);
	if (map_idx == DRA_BPF_MAP_SCTP_IP_NAT)
		list_add_tail(&new->next, &daemon_data->sctp_ip_nat_rules);
	return 0;
}

static int
dra_bpf_nat_insert(vty_t *vty, int type, int map_idx, int argc, const char **argv)
{
	list_head_t *l = &daemon_data->bpf_progs;
	dra_bpf_opts_t *opts;
	uint32_t key, addr, netmask;
	int err;

	if (argc < 4) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	opts = dra_bpf_opts_get_by_label(l, argv[0]);
	if (!opts) {
		vty_out(vty, "%% unknown BPF prog with label:%s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!inet_ston(argv[1], &key)) {
		vty_out(vty, "%% malformed IP Address:%s%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!inet_ston(argv[2], &addr)) {
		vty_out(vty, "%% malformed IP Address:%s%s", argv[2], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!inet_ston(argv[3], &netmask)) {
		vty_out(vty, "%% malformed IP Address:%s%s", argv[3], VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = dra_nat_rule_alloc(opts, type, map_idx, key, addr, netmask);
	if (err) {
		vty_out(vty, "%% Error setting NAT rule for label:%s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

int
dra_bpf_arp_ip_nat_insert(vty_t *vty, int argc, const char **argv)
{
	return dra_bpf_nat_insert(vty, 0, DRA_BPF_MAP_ARP_IP_NAT, argc, argv);
}

int
dra_bpf_ip_nat_insert(vty_t *vty, int type, int argc, const char **argv)
{
	return dra_bpf_nat_insert(vty, type, DRA_BPF_MAP_IP_NAT, argc, argv);
}

int
dra_bpf_sctp_ip_nat_insert(vty_t *vty, int argc, const char **argv)
{
	return dra_bpf_nat_insert(vty, 0, DRA_BPF_MAP_SCTP_IP_NAT, argc, argv);
}

/*
 *	NAT related
 */
int
dra_nat_destroy(void)
{
	dra_nat_rule_t *r, *_r;

	list_for_each_entry_safe(r, _r, &daemon_data->arp_ip_nat_rules, next)
		FREE(r);
	list_for_each_entry_safe(r, _r, &daemon_data->ip_nat_rules, next)
		FREE(r);
	list_for_each_entry_safe(r, _r, &daemon_data->sctp_ip_nat_rules, next)
		FREE(r);
	return 0;
}
