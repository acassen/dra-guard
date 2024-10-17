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

#ifndef _DRA_DIAMETER_H
#define _DRA_DIAMETER_H

/* Defines */
#define DIAMETER_AVP_BUFSIZE	(1 << 10)

/* Diameter protocol headers */
#define DIAMETER_PORT		3868
#define DIAMETER_PROTO_VERSION	0x01
#define DIAMETER_MAX_AVP_PARSED	64
#define DIAMETER_MAX_APN_PARSED	32
#define PAD4(_x) ((_x) + ( (4 - (_x)) & 3 ))
#define DIAMETER_VSPEC_GET_FL(X) ((X) | 0xff000000)
#define DIAMETER_GET_ULONG(X) (ntohl((X)) & 0x00ffffff)
#define DIAMETER_VSPEC_FL	0xc0000000
#define VENDOR_3GPP		10415UL

/* Command-Code */
#define CC_3GPP_CMD_UL			316UL

/* AVP Flags */
#define AVP_FL_VENDOR			0x80
#define AVP_FL_MANDATORY		0x40

/* AVP-Code */
#define AC_3GPP_ORIGIN_HOST		264UL
#define AC_3GPP_ORIGIN_REALM		296UL
#define AC_3GPP_MSISDN			701UL
#define AC_3GPP_ULA_FL			1406UL
#define AC_3GPP_SUBS_DATA		1400UL
#define AC_3GPP_APN_CONF_PROFILE	1429UL
#define AC_3GPP_APN_CONF		1430UL
#define AC_3GPP_MIP6_AGENT_INFO		486UL
#define AC_3GPP_MIP_HOME_AGENT_HOST	348UL
#define AC_3GPP_DESTINATION_HOST	293UL
#define AC_3GPP_DESTINATION_REALM	283UL
#define AC_3GPP_PDN_GW_ALLOC_TYPE	1438UL
#define AC_3GPP_SERVICE_SELECTION	493UL
#define AC_3GPP_SPECIFIC_APN_INFO	1472UL
#define AC_3GPP_CONTEXT_IDENTIFIER	1423UL

typedef struct _msg_hdr {
	uint32_t	msg_length;		/* (READONLY)(3 bytes) indicates the length of the message */
	uint32_t	msg_code;		/* (3 bytes) the command-code. */
	uint32_t	msg_appl;		/* The application issuing this message */
	uint32_t	msg_hbhid;		/* The Hop-by-Hop identifier of the message */
	uint32_t	msg_eteid;		/* The End-to-End identifier of the message */
} msg_hdr_t;

typedef struct _avp_hdr {
	uint32_t	avp_code;		/* the AVP Code */
	uint32_t	avp_len;		/* (READONLY)(Only 3 bytes are used) */
} avp_hdr_t;

typedef struct _avp_vendor {
	uint32_t	avp_vendor;		/* Only used if AVP_FLAG_VENDOR is present */
} avp_vendor_t;

typedef struct _avp_node {
	avp_hdr_t	*avph;
	uint8_t		*data;			/* pointer to the value of the AVP. */
} avp_node_t;

typedef struct _msg_root {
	msg_hdr_t	*msgh;
	avp_node_t	*avp;
} msg_root_t;

typedef struct _avp_ctx {
	msg_root_t	*root;
	avp_node_t	*avp_w0;
	avp_node_t	*avp_w1;
	avp_node_t	*avp_w2;
	uint8_t		avp_mai[DIAMETER_AVP_BUFSIZE];	/* MIP6-Agent-Info */
	int		avp_mai_len;
} avp_ctx_t;


/* Prototypes */
extern uint8_t *avp_get(uint32_t, uint8_t *, uint8_t *);
extern avp_node_t *avp_parse(avp_node_t *, uint32_t, uint8_t *, uint8_t *);
extern void avp_len_update_delta(avp_hdr_t *, int, uint8_t);
extern void msg_len_update_delta(msg_hdr_t *, int, uint8_t);
extern msg_root_t *msg_parse_apn_conf_profil_path(avp_ctx_t *, pkt_buffer_t *);
extern int avp_mip6_agent_info_update(avp_ctx_t *, avp_node_t *, uint8_t *, int, pkt_buffer_t *);
extern int avp_build_mip6_agent_info(dra_mip6_agent_info_t *);
extern int avp_build_mip6_agent_info_dynamic(avp_ctx_t *, dra_mip6_agent_info_t *, pkt_buffer_t *);
extern avp_ctx_t *avp_ctx_alloc(void);
extern void avp_ctx_destroy(avp_ctx_t *);

#endif
