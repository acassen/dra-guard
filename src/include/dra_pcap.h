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

#ifndef _DRA_PCAP_H
#define _DRA_PCAP_H

/* Defines */
#define DRA_PCAP_BUFSIZE	(1 << 13)
#define DRA_PCAP_FILESIZE	256
#define DRA_PCAP_PATH		512

/* flags */
enum dra_pcap_flags {
	DRA_PCAP_FL_OPEN_BIT,
};

/* MIP related */
typedef struct _dra_pcap {
	char		filename[DRA_PCAP_FILESIZE];
	char		path[DRA_PCAP_PATH];
	unsigned char	buffer[DRA_PCAP_BUFSIZE];
	pcap_t		*pcap;
	pcap_dumper_t	*dumper;
	pthread_mutex_t	mutex;

	unsigned long	flags;
} dra_pcap_t;

/* Prototypes */
extern void dra_pcap_pkt_write(dra_pcap_t *, pkt_buffer_t *, int);
extern dra_pcap_t *dra_pcap_alloc(const char *);
extern void dra_pcap_destroy(dra_pcap_t *);

#endif
