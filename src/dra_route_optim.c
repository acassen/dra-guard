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
#include <pcap/pcap.h>
#include <errno.h>

/* local includes */
#include "dra_guard.h"
#include "dra_pcap.h"

/* Extern data */
extern data_t *daemon_data;

static int64_t
bcd_to_int64(const uint8_t *buffer, size_t size)
{
	int64_t value = 0;
	uint8_t high, low;
	int i;

	/* With bit swapping */
	for (i = 0; i < size; i++) {
		low = (buffer[i] & 0xf0) >> 4;
		high = buffer[i] & 0x0f;
		if (high > 9)
			return value;
		value = (value * 10) + high;

		if (low > 9)
			return value;
		value = (value * 10) + low;
	}

	return value;
}


static dra_debug_entry_t *
avp_msisdn_match(uint8_t *data, uint8_t *data_end, unsigned long flags)
{
	dra_debug_entry_t *e;
	avp_hdr_t *avph;
	uint8_t *cp;
	int offset;
	uint64_t msisdn;

	cp = avp_get(AC_3GPP_MSISDN, data, data_end);
	if (!cp)
		return NULL;

	avph = (avp_hdr_t *) cp;
	offset = sizeof(avp_hdr_t) + ((avph->avp_len & AVP_FL_VENDOR) ? sizeof(avp_vendor_t) : 0);
	cp += offset;

	msisdn = bcd_to_int64(cp, DIAMETER_GET_ULONG(avph->avp_len) - offset);
	e = dra_debug_entry_get(&daemon_data->debug_target, msisdn);
	if (!e)
		return NULL;

	log_message(LOG_INFO, "%s(): Rewriting ULA for msisdn:%ld", __FUNCTION__, msisdn);
	return e;
}

/*
 *	Diameter Route Optimization based on static local match.
 *
 * Route Optimization is a way to optimize traffic by selecting nexthop peer.
 * In our use-case here nexthop peer is a pGW. In some advanced Core-Network
 * architecture some pGW can be specialized in handling certain class of traffic
 * for QoS or any agreements with third party to offer best quality.
 * 
 * This is regular IP routings but applied to mobile network. Basic IP router is
 * routing traffic by performing IP routing table lookup to find nexthop.
 * 
 * In our special use-case here we are performing local static lookup just as a
 * PoC example, but more advanced code can select nexthop based on dynamic
 * metrics such as nexthop reachability, load, latency, proximity, ...
 * Nexthop selection is based on tweaking diameter AVP MIP6-Agent-Info present in
 * APN-Configuration-Profile of Update-Location-Answer messages. With a special
 * care for Wildcard APN handling where you need to convert Specific-APN-Info into
 * a collection of APN-Configuration.
 * MIP6-Agent-Info will over-ride MME NAPTR resolution so this concept can also
 * be used as an extension to MME NAPTR resolution process.
 */
int
dra_route_optimization(pkt_buffer_t *pkt, void *arg, dra_mip6_agent_info_t *static_mip)
{
	msg_hdr_t *msgh = (msg_hdr_t *) pkt->head;
	dra_sctp_worker_t *w = arg;
	avp_ctx_t *ctx = w->avp_ctx;
	dra_sctp_proxy_t *p = w->proxy;
	avp_node_t *avp_apn, *avp_subsd;
	dra_mip6_agent_info_t *mip = static_mip;
	dra_debug_entry_t *e;
	msg_root_t *msg_root;
	uint8_t *avp_data;
	int delta, err;

	if (DIAMETER_GET_ULONG(msgh->msg_code) != CC_3GPP_CMD_UL)
		return -1;

	avp_data = avp_get(AC_3GPP_ULA_FL, pkt->head+sizeof(msg_hdr_t), pkt->end);
	if (!avp_data)
		return -1;

	if (!(__test_bit(SCTP_FL_MATCH_TARGET_REWRITE_ULA, &p->flags) ||
	      __test_bit(SCTP_FL_REWRITE_ULA, &p->flags)))
		return -1;

	/* APN-Configuration-Profile */
	msg_root = msg_parse_apn_conf_profil_path(ctx, pkt);
	if (!msg_root)
		return -1;

	avp_apn = avp_parse(ctx->avp_w0, AC_3GPP_APN_CONF, msg_root->avp[1].data, pkt->end);
	if (!avp_apn)
		return -1;

	if (__test_bit(SCTP_FL_MATCH_TARGET_REWRITE_ULA, &p->flags)) {
		/* MSISDN Match */
		avp_subsd = &msg_root->avp[0];
		e = avp_msisdn_match(avp_subsd->data, avp_subsd->data + DIAMETER_GET_ULONG(avp_subsd->avph->avp_len)
						    , p->flags);
		if (!e)
			return -1;

		mip = e->mip;
		dra_debug_entry_put(e);
	}

	/* No static_mip nor local match */
	if (!mip)
		return -1;

	/* Save original pkt */
	if (__test_bit(MIP_FL_WRITE_PCAP_BIT, &mip->flags))
		dra_pcap_pkt_write(mip->pcap, pkt, 1);

	/* Update Agent-Host */
	if (__test_bit(MIP_FL_DYNAMIC_REALM_ORIGIN_BIT, &mip->flags) &&
	    __test_bit(MIP_FL_STATIC_HOST_BIT, &mip->flags)) {
		err = avp_build_mip6_agent_info_dynamic(ctx, mip, pkt);
		if (err) {
			log_message(LOG_INFO, "%s(): unable to build MIP6-Agent-Info...");
			return -1;
		}

		delta = avp_mip6_agent_info_update(ctx, avp_apn, ctx->avp_mai, ctx->avp_mai_len, pkt);
	} else {
		delta = avp_mip6_agent_info_update(ctx, avp_apn, mip->agent, mip->agent_len, pkt);
	}

	/* Update parents AVPs */
	avp_len_update_delta(msg_root->avp[0].avph, delta, AVP_FL_MANDATORY|AVP_FL_VENDOR);
	avp_len_update_delta(msg_root->avp[1].avph, delta, AVP_FL_MANDATORY|AVP_FL_VENDOR);
	msg_len_update_delta(msg_root->msgh, delta, DIAMETER_PROTO_VERSION);

	/* Update Pkt */
	pkt_buffer_set_end_pointer(pkt, DIAMETER_GET_ULONG(((msg_hdr_t *) pkt->head)->msg_length));
	pkt_buffer_reset_data(pkt);

	/* Save modified pkt */
	if (__test_bit(MIP_FL_WRITE_PCAP_BIT, &mip->flags))
		dra_pcap_pkt_write(mip->pcap, pkt, 2);
	return 0;
}
