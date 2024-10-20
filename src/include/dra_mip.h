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

#ifndef _DRA_MIP_H
#define _DRA_MIP_H

/* Defines */
#define MIP_DST_BUFSIZE		(1 << 8)
#define MIP_AVP_BUFSIZE		(1 << 10)
#define MIP_NAME_MAX_LEN	16

/* flags */
enum mip_flags {
	MIP_FL_STATIC_HOST_BIT,
	MIP_FL_STATIC_REALM_BIT,
	MIP_FL_DYNAMIC_REALM_ORIGIN_BIT,
	MIP_FL_WILDCARD_APN_XFRM_BIT,
	MIP_FL_WRITE_PCAP_BIT,
};

/* MIP related */
typedef struct _dra_mip6_agent_info {
	char		name[MIP_NAME_MAX_LEN];
	char		destination_host[MIP_DST_BUFSIZE];
	char		destination_realm[MIP_DST_BUFSIZE];
	uint8_t		agent[MIP_AVP_BUFSIZE];
	int		agent_len;
	void		*pcap;

	list_head_t	next;

	unsigned long	flags;
} dra_mip6_agent_info_t;

/* Prototypes */
extern dra_mip6_agent_info_t *dra_mip_get(const char *);
extern dra_mip6_agent_info_t *dra_mip_alloc(const char *);
extern int dra_mip_release(const char *);
extern int dra_mip_destroy(void);

#endif
