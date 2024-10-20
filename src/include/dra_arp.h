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

#ifndef _DRA_ARP_H
#define _DRA_ARP_H

/* defines */
#define ARP_BUFSIZE	(1 << 10)

/* flags */
enum arp_flags {
	ARP_FL_STOPPING_BIT,
	ARP_FL_RUNNING_BIT,

};

/* ARP related */
typedef struct _arphdr_eth {
	__be16		ar_hrd;			/* format of hardware address   */
	__be16		ar_pro;			/* format of protocol address   */
	unsigned char	ar_hln;			/* length of hardware address   */
	unsigned char	ar_pln;			/* length of protocol address   */
	__be16		ar_op;			/* ARP opcode (command)         */

	/* Ethernet specific */
	unsigned char	ar_sha[ETH_ALEN];	/* sender hardware address      */
	uint32_t	ar_sip;			/* sender IP address            */
	unsigned char	ar_tha[ETH_ALEN];	/* target hardware address      */
	uint32_t	ar_tip;			/* target IP address            */
} __attribute__((packed)) arphdr_eth_t;

typedef struct _dra_arp_t {
	char		ifname[IFNAMSIZ];
	int		ifindex;
	unsigned char	hwaddr[ETH_ALEN];
	char		buffer[ARP_BUFSIZE];
	uint32_t	ip_address;
	pthread_t	task;

	list_head_t	next;

	unsigned long	flags;
} dra_arp_t;

/* Prototypes */
extern int dra_arp_start(dra_arp_t *);
extern dra_arp_t *dra_arp_init(int, const char *, uint32_t);
extern int dra_arp_release(int, uint32_t);
extern int dra_arp_destroy(void);

#endif
