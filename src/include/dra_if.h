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

#ifndef _DRA_IF_H
#define _DRA_IF_H

/* Defines */
#define IF_DEFAULT_CONNECTION_KEEPIDLE		20
#define IF_DEFAULT_CONNECTION_KEEPCNT		2
#define IF_DEFAULT_CONNECTION_KEEPINTVL		10

/* Prototypes */
extern int if_setsockopt_reuseaddr(int, int);
extern int if_setsockopt_nolinger(int, int);
extern int if_setsockopt_tcpcork(int, int);
extern int if_setsockopt_nodelay(int, int);
extern int if_setsockopt_keepalive(int, int);
extern int if_setsockopt_tcp_keepidle(int, int);
extern int if_setsockopt_tcp_keepcnt(int, int);
extern int if_setsockopt_tcp_keepintvl(int, int);
extern int if_setsockopt_rcvtimeo(int, int);
extern int if_setsockopt_sndtimeo(int, int);
extern int if_setsockopt_reuseport(int, int);
extern int if_setsockopt_hdrincl(int);
extern int if_setsockopt_broadcast(int);
extern int if_setsockopt_promisc(int, int, bool);
extern int if_setsockopt_attach_bpf(int, int);
extern int if_setsockopt_no_receive(int *);
extern int if_setsockopt_rcvbuf(int *, int);
extern int if_setsockopt_bindtodevice(int *, const char *);
extern int if_setsockopt_priority(int *, int);
extern int if_nametohwaddr(const char *, unsigned char *, size_t);
extern int if_setsockopt_sctp_initmsg(int, struct sctp_initmsg *);
extern int if_setsockopt_sctp_events(int, struct sctp_event_subscribe *);
extern int if_setsockopt_sctp_nodelay(int, int);
extern int if_getsockopt_sctp_status(int, struct sctp_status *);

#endif
