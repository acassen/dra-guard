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

#ifndef _DRA_BPF_NAT_H
#define _DRA_BPF_NAT_H

/* defines */


/* NAT related */
typedef struct _dra_nat_rule {
	uint8_t			type;
	uint32_t		key;
	uint32_t		addr;
	uint32_t		netmask;

	dra_bpf_opts_t		*opts;

	list_head_t		next;
} dra_nat_rule_t;

/* Prototypes */
extern int dra_bpf_arp_ip_nat_insert(vty_t *, int, const char **);
extern int dra_bpf_ip_nat_insert(vty_t *, int, int, const char **);
extern int dra_bpf_sctp_ip_nat_insert(vty_t *, int, const char **);
extern int dra_nat_destroy(void);

#endif
