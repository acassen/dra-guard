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

#ifndef _DRA_BPF_H
#define _DRA_BPF_H

/* defines */
#define DRA_XDP_STRERR_BUFSIZE	(1 << 7)
#define XDP_PATH_MAX		(1 << 7)

enum dra_bpf_prog_type {
	BPF_PROG_QDISC = 0,
	BPF_PROG_XDP,
};

/* MAP Entries*/
enum {
	DRA_BPF_MAP_ARP_IP_NAT = 0,
	DRA_BPF_MAP_IP_NAT,
	DRA_BPF_MAP_SCTP_IP_NAT,
	DRA_BPF_MAP_CNT
};

struct ip_nat_rule {
	__u8	type;
	__u32	addr;
	__u32	netmask;
}__attribute__ ((__aligned__(8)));
#define DRA_IP_NAT_SRC_DST	0
#define DRA_IP_NAT_SRC		1
#define DRA_IP_NAT_DST		2

/* BPF related */
typedef struct _dra_bpf_maps {
	struct bpf_map		*map;
} dra_bpf_maps_t;

typedef struct _dra_bpf_opts {
	char			label[DRA_STR_MAX_LEN];
	int			type;
	char			filename[DRA_STR_MAX_LEN];
	char			progname[DRA_STR_MAX_LEN];
	int			ifindex;
	char			pin_root_path[DRA_STR_MAX_LEN];
	struct bpf_object	*bpf_obj;
	struct bpf_link		*bpf_lnk;
	dra_bpf_maps_t		*bpf_maps;
	vty_t			*vty;

	void (*bpf_unload) (struct _dra_bpf_opts *);

	list_head_t		next;
} dra_bpf_opts_t;


/* Prototypes */
extern int dra_bpf_map_load(dra_bpf_opts_t *);
extern struct bpf_map *dra_bpf_load_map(struct bpf_object *, const char *);
extern dra_bpf_opts_t *dra_bpf_opts_alloc(int, void (*bpf_unload) (dra_bpf_opts_t *));
extern int dra_bpf_opts_add(dra_bpf_opts_t *, list_head_t *);
extern int dra_bpf_opts_del(dra_bpf_opts_t *);
extern dra_bpf_opts_t *dra_bpf_opts_exist(list_head_t *, int, const char **);
extern dra_bpf_opts_t *dra_bpf_opts_get_by_label(list_head_t *, const char *);
extern void dra_bpf_opts_destroy(list_head_t *);
extern int dra_bpf_opts_load(dra_bpf_opts_t *, vty_t *, int, const char **,
			     int (*bpf_load) (dra_bpf_opts_t *));
extern int dra_xdp_load(dra_bpf_opts_t *);
extern void dra_xdp_unload(dra_bpf_opts_t *);
extern int dra_qdisc_clsact_load(dra_bpf_opts_t *);
extern void dra_qdisc_clast_unload(dra_bpf_opts_t *);
extern int dra_bpf_init(void);
extern int dra_bpf_destroy(void);

#endif
