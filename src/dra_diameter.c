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
#include <pcap/pcap.h>
#include <errno.h>

/* local includes */
#include "dra_guard.h"
#include "dra_pcap.h"

/* Extern data */
extern data_t *daemon_data;


/*
 *	Diameter Protocol helpers
 */
#if 0
static uint32_t avp_dst_host_path[] = {
	AC_3GPP_SUBS_DATA,
	AC_3GPP_APN_CONF_PROFILE,
	AC_3GPP_APN_CONF,
	AC_3GPP_MIP6_AGENT_INFO,
	AC_3GPP_MIP_HOME_AGENT_HOST,
	AC_3GPP_DESTINATION_HOST,
	0
};
#endif

static uint32_t avp_apn_conf_profil_path[] = {
	AC_3GPP_SUBS_DATA,
	AC_3GPP_APN_CONF_PROFILE,
	0
};

static uint32_t avp_mip6_agent_info_path[] = {
	AC_3GPP_MIP6_AGENT_INFO,
	0
};

#if 0
static uint32_t avp_home_agent_host_path[] = {
	AC_3GPP_MIP6_AGENT_INFO,
	AC_3GPP_MIP_HOME_AGENT_HOST,
	0
};
#endif

#if 0
static void
avp_dump(uint8_t *data)
{
	avp_hdr_t *avph = (avp_hdr_t *) data;
	int offset, len;

	offset = sizeof(avp_hdr_t);
	offset += (avph->avp_len & AVP_FL_VENDOR) ? sizeof(avp_vendor_t) : 0;
	len = PAD4(DIAMETER_GET_ULONG(avph->avp_len)) - offset;

	printf("---[ AVP Code:%d len:%d ]---\n",
	       ntohl(avph->avp_code), DIAMETER_GET_ULONG(avph->avp_len));
	dump_buffer("AVP ", (char *) data, PAD4(DIAMETER_GET_ULONG(avph->avp_len)));
	dump_buffer("AVP-Header ", (char *) data, offset);
	dump_buffer("AVP-Data   ", (char *) (data + offset), len);
}

static int
avps_dump(avp_node_t *avp)
{
	avp_hdr_t *avph;
	int i, offset, len;

	if (!avp)
		return -1;

	for (i = 0; avp[i].data && i < DIAMETER_MAX_AVP_PARSED; i++) {
		printf("---[ AVP-Code:%d ]---\n", ntohl(avp[i].avph->avp_code));
		avph = avp[i].avph;
		offset = sizeof(avp_hdr_t);
		offset += (avph->avp_len & AVP_FL_VENDOR) ? sizeof(avp_vendor_t) : 0;
		len = PAD4(DIAMETER_GET_ULONG(avph->avp_len)) - offset;
		dump_buffer("AVP-DATA ", (char *) avp[i].data, len);
	}

	return 0;
}
#endif

static int
avp_delete(uint8_t *data, pkt_buffer_t *pkt)
{
	avp_hdr_t *avph = (avp_hdr_t *) data;
	int delta = PAD4(DIAMETER_GET_ULONG(avph->avp_len));
	int len = pkt_buffer_len(pkt) - delta;
	int tail_len = pkt->end - (data + delta);

	memmove(data, data + delta, tail_len);
	pkt_buffer_set_end_pointer(pkt, len);

	return -delta;
}

uint8_t *
avp_get(uint32_t code, uint8_t *data, uint8_t *data_end)
{
	avp_hdr_t *avph;
	uint8_t *cp;

	for (cp = data; cp < data_end; cp += PAD4(DIAMETER_GET_ULONG(avph->avp_len))) {
		avph = (avp_hdr_t *) cp;
		if (cp + sizeof(avp_hdr_t) > data_end)
			return NULL;

		/* Prevent infinite loop from bogus zeroed avp->len */
		if (!DIAMETER_GET_ULONG(avph->avp_len))
			return NULL;

		if (ntohl(avph->avp_code) == code)
			return cp;
	}

	return NULL;
}

avp_node_t *
avp_parse(avp_node_t *node, uint32_t code, uint8_t *data, uint8_t *data_end)
{
	avp_hdr_t *avph;
	int i = 0, offset;
	uint8_t *cp;

	memset(node, 0, sizeof(avp_node_t) * DIAMETER_MAX_APN_PARSED);

	for (cp = data; i < DIAMETER_MAX_APN_PARSED && cp < data_end;
	     cp += PAD4(DIAMETER_GET_ULONG(avph->avp_len))) {
		avph = (avp_hdr_t *) cp;
		if (cp + sizeof(avp_hdr_t) > data_end)
			return NULL;

		/* Prevent infinite loop from bogus zeroed avp->len */
		if (!DIAMETER_GET_ULONG(avph->avp_len))
			return NULL;

		if (ntohl(avph->avp_code) != code)
			continue;

		offset = sizeof(avp_hdr_t);
		offset += (avph->avp_len & AVP_FL_VENDOR) ? sizeof(avp_vendor_t) : 0;
		node[i].avph = avph;
		node[i++].data = cp + offset;
	}

	return (i) ? node : NULL;
}

static avp_node_t *
avp_parse_path(avp_node_t *node, uint32_t *avp_path, uint8_t *data, uint8_t *data_end)
{
	avp_hdr_t *avph;
	int i, offset;
	uint8_t *cp;

	memset(node, 0, sizeof(avp_node_t) * DIAMETER_MAX_APN_PARSED);

	for (i = 0, cp = data; avp_path[i] && cp < data_end; i++, cp += offset) {
		cp = avp_get(avp_path[i], cp, data_end);
		if (!cp)
			return NULL;

		avph = (avp_hdr_t *) cp;
		if (cp + sizeof(avp_hdr_t) > data_end)
			return NULL;

		/* Prevent infinite loop from bogus zeroed avp->len */
		if (!DIAMETER_GET_ULONG(avph->avp_len))
			return NULL;

		offset = sizeof(avp_hdr_t);
		offset += (avph->avp_len & AVP_FL_VENDOR) ? sizeof(avp_vendor_t) : 0;
		node[i].avph = avph;
		node[i].data = cp + offset;
	}

	return node;
}

void
avp_len_update_delta(avp_hdr_t *avph, int delta, uint8_t flags)
{
	int len = DIAMETER_GET_ULONG(avph->avp_len) + delta;
	avph->avp_len = htonl(len) | flags;
}

#if 0
static void
msg_dump(msg_root_t *root)
{
	printf("AVP_ROOT->code:%d\n", DIAMETER_GET_ULONG(root->msgh->msg_code));
	avps_dump(root->avp);
}
#endif

void
msg_len_update_delta(msg_hdr_t *msgh, int delta, uint8_t flags)
{
	int len = DIAMETER_GET_ULONG(msgh->msg_length) + delta;
	msgh->msg_length = htonl(len) | flags;
}

static msg_root_t *
msg_parse_path(avp_ctx_t *ctx, uint32_t *avp_path, uint8_t *data, uint8_t *data_end)
{
	msg_root_t *root = ctx->root;
	uint8_t *cp = data + sizeof(msg_hdr_t);
	avp_hdr_t *avph;
	int i=0, offset=0;

	root->msgh = (msg_hdr_t *) data;
	memset(root->avp, 0, sizeof(avp_node_t) * DIAMETER_MAX_AVP_PARSED);

	for (i = 0; avp_path[i] && cp < data_end; i++, cp += offset) {
		cp = avp_get(avp_path[i], cp, data_end);
		if (!cp)
			return NULL;

		avph = (avp_hdr_t *) cp;
		if (cp + sizeof(avp_hdr_t) > data_end)
			return NULL;

		offset = sizeof(avp_hdr_t);
		offset += (avph->avp_len & AVP_FL_VENDOR) ? sizeof(avp_vendor_t) : 0;
		root->avp[i].avph = avph;
		root->avp[i].data = cp + offset;
	}

	return root;
}

msg_root_t *
msg_parse_apn_conf_profil_path(avp_ctx_t *ctx, pkt_buffer_t *pkt)
{
	return msg_parse_path(ctx, avp_apn_conf_profil_path, pkt->head, pkt->end);
}

static int
avp_mip6_agent_info_replace(avp_node_t *avp, uint8_t *mip, int mip_len, pkt_buffer_t *pkt)
{
	uint8_t *cp = (uint8_t *)avp->avph;
	int delta = 0, tail_len;

	delta = DIAMETER_GET_ULONG(avp->avph->avp_len) - mip_len;
	tail_len = pkt->end - (cp + DIAMETER_GET_ULONG(avp->avph->avp_len));

	if (delta < 0) {
		/* Bounds checking */
		if (pkt_buffer_tailroom(pkt) < -delta) {
			log_message(LOG_INFO, "%s(): Warning Bounds Check failed pkt_tailroom:%d delta:%d !!!"
					    , __FUNCTION__
					    , pkt_buffer_tailroom(pkt), -delta);
			return 0;
		}

		cp += DIAMETER_GET_ULONG(avp->avph->avp_len);
		memmove(cp - delta, cp, tail_len);
	}

	/* cumulative case including delta == 0 */
	memcpy((uint8_t *)avp->avph, mip, mip_len);
	
	if (delta > 0) {
		cp += mip_len;
		memmove(cp, cp + delta, tail_len);
	}

	return -delta;
}

static int
avp_pdn_gw_alloc_type_set(uint8_t *data, uint32_t value)
{
	uint32_t *alloc_type = (uint32_t *) (data + sizeof(avp_hdr_t) + sizeof(avp_vendor_t));
	*alloc_type = htonl(value);
	return 0;
}

static int
avp_mip6_agent_info_insert(avp_node_t *avp, uint8_t *mip, int mip_len, pkt_buffer_t *pkt)
{
	uint8_t *cp = (uint8_t *)avp->avph;
	avp_hdr_t *avph;
	uint8_t *avp_end;
	avp_vendor_t *vendor;
	int pdn_gw_alloc_type_len, tail_len;

	avp_end = cp + DIAMETER_GET_ULONG(avp->avph->avp_len);
	tail_len = pkt->end - avp_end;
	pdn_gw_alloc_type_len = sizeof(avp_hdr_t) + sizeof(avp_vendor_t) + sizeof(uint32_t);

	/* Bounds checking */
	if (pkt_buffer_tailroom(pkt) < mip_len + pdn_gw_alloc_type_len) {
		log_message(LOG_INFO, "%s(): Warning Bounds Check failed pkt_tailroom:%d delta:%d !!!"
					, __FUNCTION__
					, pkt_buffer_tailroom(pkt)
					, mip_len + pdn_gw_alloc_type_len);
		return 0;
	}

	memmove(avp_end + mip_len + pdn_gw_alloc_type_len, avp_end, tail_len);
	memcpy(avp_end, mip, mip_len);

	cp = avp_end + mip_len;
	avph = (avp_hdr_t *) cp;
	avph->avp_code = htonl(AC_3GPP_PDN_GW_ALLOC_TYPE);
	avph->avp_len = htonl(pdn_gw_alloc_type_len) | AVP_FL_MANDATORY|AVP_FL_VENDOR;
	vendor = (avp_vendor_t *) (cp + sizeof(avp_hdr_t));
	vendor->avp_vendor = htonl(VENDOR_3GPP);
	avp_pdn_gw_alloc_type_set(cp, 0);

	return mip_len + pdn_gw_alloc_type_len;
}

static bool
avp_service_selection_is_wildcard(uint8_t *data)
{
	avp_hdr_t *avph = (avp_hdr_t *) data;
	uint8_t *cp;

	if (DIAMETER_GET_ULONG(avph->avp_len) != 9)
		return false;

	cp = (uint8_t *) (data + sizeof(avp_hdr_t));

	return (*cp == '*');
}

static void
avp_buffer_offset_update(avp_node_t *avps, int i, int delta)
{
	avp_node_t *avp = &avps[i];
	int j;

	/* Update parents AVP len */
	avp_len_update_delta(avp->avph, delta, AVP_FL_VENDOR|AVP_FL_MANDATORY);

	/* re-sync following buffer offset */
	for (j = i+1; j < DIAMETER_MAX_APN_PARSED && avps[j].data; j++) {
		avp = &avps[j];
		avp->avph = (avp_hdr_t *) ((uint8_t *)avp->avph + delta);
		avp->data += delta;
	}
}

static int
avp_service_selection_cmp(uint8_t *a, uint8_t *b)
{
	int len_a = DIAMETER_GET_ULONG(((avp_hdr_t *) a)->avp_len);
	int len_b = DIAMETER_GET_ULONG(((avp_hdr_t *) b)->avp_len);
	int offset = sizeof(avp_hdr_t);

	if (len_a != len_b)
		return -1;

	return memcmp(a + offset, b + offset, len_a);
}

static bool
apn_configuration_exist(avp_node_t *avps, avp_node_t *avp_apn_wildcard, uint8_t *service_selection)
{
	avp_node_t *avp;
	uint8_t *avp_end, *avp_data;
	int i;

	for (i = 0; i < DIAMETER_MAX_APN_PARSED && avps[i].data; i++) {
		avp = &avps[i];

		/* skip wildcard APN...*/
		if (avp == avp_apn_wildcard)
			continue;

		avp_end = (uint8_t *)avp->avph + DIAMETER_GET_ULONG(avp->avph->avp_len);

		avp_data = avp_get(AC_3GPP_SERVICE_SELECTION, avp->data, avp_end);
		if (avp_data) {
			if (!avp_service_selection_cmp(avp_data, service_selection))
				return true;
		}
	}

	return false;
}

static int
avp_build(uint8_t *buffer, int offset, uint32_t code, uint8_t flags)
{
	avp_hdr_t *avph;
	avp_vendor_t *vendor;
	int len = sizeof(avp_hdr_t);

	len += (flags & AVP_FL_VENDOR) ? sizeof(avp_vendor_t) : 0;
	if (!buffer)
		return len;

	avph = (avp_hdr_t *) (buffer + offset);
	avph->avp_code = htonl(code);
	avph->avp_len = htonl(len) | flags;
	vendor = (avp_vendor_t *) (buffer + offset + sizeof(avp_hdr_t));
	vendor->avp_vendor = htonl(VENDOR_3GPP);

	return len;
}

static int
avp_copy(uint8_t *dst, int offset, uint8_t *src, uint8_t *end)
{
	avp_hdr_t *avph = (avp_hdr_t *) src;
	int len = PAD4(DIAMETER_GET_ULONG(avph->avp_len));

	if (!dst)
		return len;

	/* Bound checking */
	if (dst + offset + len > end) {
		log_message(LOG_INFO, "%s(): bound-checking failed !!! (ignoring)..."
					, __FUNCTION__);
		return 0;
	}

	memcpy(dst + offset, src, len);

	return len;
}

static void
avp_context_id_update(uint8_t *buffer, int id, uint8_t *end)
{
	avp_hdr_t *avph;
	uint8_t *cp;
	uint32_t *context_id;
	int offset = sizeof(avp_hdr_t);

	if (!buffer)
		return;

	cp = avp_get(AC_3GPP_CONTEXT_IDENTIFIER, buffer, end);
	if (!cp)
		return;

	avph = (avp_hdr_t *) cp;
	offset += (avph->avp_len & AVP_FL_VENDOR) ? sizeof(avp_vendor_t) : 0;
	context_id = (uint32_t *) (cp + offset);
	*context_id = htonl(id);
}

static int
avp_pdn_gw_allocation_type_add(uint8_t *buffer, int offset, uint8_t *end)
{
	int len = avp_build(buffer, offset, AC_3GPP_PDN_GW_ALLOC_TYPE, AVP_FL_MANDATORY|AVP_FL_VENDOR);
	avp_hdr_t *avph;

	len += sizeof(uint32_t);

	if (!buffer)
		return len;

	avph = (avp_hdr_t *) (buffer + offset);
	avph->avp_len = htonl(DIAMETER_GET_ULONG(avph->avp_len) + sizeof(uint32_t)) | AVP_FL_MANDATORY|AVP_FL_VENDOR;
	avp_pdn_gw_alloc_type_set(buffer + offset, 0);

	return len;
}

static int
apn_configuration_build(int id, avp_node_t *avp
			      , avp_node_t *avp_apn_wildcard, int avp_apn_wildcard_offset
			      , uint8_t *mip
			      , pkt_buffer_t *pkt)
{
	uint8_t *service_selection;
	uint8_t *avp_end = (uint8_t *)avp->avph + DIAMETER_GET_ULONG(avp->avph->avp_len);
	avp_hdr_t *avph;
	int tail_len, offset = 0, phase = 0;
	uint8_t *cp, *buffer, *buffer_end = NULL, *apn_wildcard_end, *append_buffer;
	uint32_t context_id_base = 1 << 24;

	service_selection = avp_get(AC_3GPP_SERVICE_SELECTION, avp->data, avp_end);
	if (!service_selection)
		return 0;

	/* Append at the end of APN wildcard buffer */
	apn_wildcard_end = (uint8_t *)avp_apn_wildcard->avph + DIAMETER_GET_ULONG(avp_apn_wildcard->avph->avp_len);
	append_buffer = apn_wildcard_end + avp_apn_wildcard_offset;

	/* In order to optimize memory access, we are performing 2 phases. Phase0 will
	 * compute space room needed, Phase1 will fill buffer accordingly if enough
	 * space is left at pkt tailroom */
  next_phase:
	/* APN-Configuration AVP*/
	buffer = (phase) ? append_buffer : NULL;
	offset = avp_build(buffer, 0, AC_3GPP_APN_CONF, AVP_FL_MANDATORY|AVP_FL_VENDOR);

	/* Cherry picking wildcard AVPs */
	for (cp = avp_apn_wildcard->data; cp < apn_wildcard_end; cp += PAD4(DIAMETER_GET_ULONG(avph->avp_len))) {
		avph = (avp_hdr_t *) cp;

		/* Bound check */
		if (cp + sizeof(avp_hdr_t) > apn_wildcard_end) {
			log_message(LOG_INFO, "%s(): bound-checking failed !!! (ignoring)..."
					    , __FUNCTION__);
			return 0;
		}

		/* Prevent infinite loop from bogus zeroed avp->len */
		if (!DIAMETER_GET_ULONG(avph->avp_len)) {
			log_message(LOG_INFO, "%s(): null AVP len detected !!! (ignoring)..."
					    , __FUNCTION__);
			return 0;
		}

		if (ntohl(avph->avp_code) == AC_3GPP_SPECIFIC_APN_INFO ||
		    ntohl(avph->avp_code) == AC_3GPP_SERVICE_SELECTION)
			continue;

		offset += avp_copy(buffer, offset, cp, buffer_end);
	}

	/* Update Context-ID */
	avp_context_id_update(buffer, context_id_base + id, buffer_end);

	/* Append Service-Selection */
	offset += avp_copy(buffer, offset, service_selection, buffer_end);

	/* Append MIP6-Agent-Info */
	offset += avp_copy(buffer, offset, mip, buffer_end);

	/* Append PDN-GW-Allocation-Type */
	offset += avp_pdn_gw_allocation_type_add(buffer, offset, buffer_end);

	if (!phase++) {
		/* If no more tailroom space is available simply skip buffer append.
		 * This is security to prevent against buffer gardening ! :) */
		if (pkt_buffer_tailroom(pkt) < offset) {
			log_message(LOG_INFO, "%s(): No more tailroom available !!! (ignoring)..."
					    , __FUNCTION__);
			return 0;
		}

		tail_len = pkt->end - append_buffer;
		memmove(append_buffer + offset, append_buffer, tail_len);
		pkt_buffer_put_end(pkt, offset);
		buffer_end = append_buffer + offset;

		goto next_phase;
	}

	avph = (avp_hdr_t *) buffer;
	avph->avp_len = htonl(offset) | AVP_FL_MANDATORY|AVP_FL_VENDOR;

	return offset;
}

static int
apn_configuration_append(avp_node_t *node, avp_node_t *avps, avp_node_t *avp_apn_wildcard,
			 uint8_t *mip, pkt_buffer_t *pkt)
{
	uint8_t *end = (uint8_t *)avp_apn_wildcard->avph + DIAMETER_GET_ULONG(avp_apn_wildcard->avph->avp_len);
	avp_node_t *avps_specific_apn_info;
	uint8_t *service_selection;
	uint8_t *avp_end;
	avp_node_t *avp;
	int i, delta = 0;

	/* We need to resync pointers here since previous stage may have altered buffer */
	avps_specific_apn_info = avp_parse(node, AC_3GPP_SPECIFIC_APN_INFO, avp_apn_wildcard->data, end);
	if (!avps_specific_apn_info)
		return 0;

	for (i = 0; i < DIAMETER_MAX_APN_PARSED && avps_specific_apn_info[i].data; i++) {
		avp = &avps_specific_apn_info[i];
		avp_end = (uint8_t *)avp->avph + DIAMETER_GET_ULONG(avp->avph->avp_len);

		service_selection = avp_get(AC_3GPP_SERVICE_SELECTION, avp->data, avp_end);
		if (!service_selection)
			continue;

		/* Do not append existing service selection */
		if (apn_configuration_exist(avps, avp_apn_wildcard, service_selection))
			continue;

		delta += apn_configuration_build(i, avp, avp_apn_wildcard, delta, mip, pkt);
	}

	return delta;
}

static int
avp_specific_apn_info_delete(avp_node_t *avp, pkt_buffer_t *pkt)
{
	int avp_len = DIAMETER_GET_ULONG(avp->avph->avp_len);
	uint8_t *data_end = (uint8_t *) avp->avph + avp_len;
	avp_hdr_t *avph;
	int delta = 0, next = 0;
	uint8_t *cp;

	for (cp = avp->data; cp < data_end; cp += next) {
		avph = (avp_hdr_t *) cp;
		if (cp + sizeof(avp_hdr_t) > data_end)
			goto end;

		next = PAD4(DIAMETER_GET_ULONG(avph->avp_len));
		if (ntohl(avph->avp_code) != AC_3GPP_SPECIFIC_APN_INFO)
			continue;

		delta += avp_delete(cp, pkt);

		/* re-sync offset*/
		data_end += delta;
		next = 0;
	}

	/* Update AVP header len accordingly */
	if (delta)
		avp_len_update_delta(avp->avph, delta, AVP_FL_VENDOR|AVP_FL_MANDATORY);

  end:
	return delta;
}

int
avp_mip6_agent_info_update(avp_ctx_t *ctx, avp_node_t *avps, uint8_t *mip, int mip_len, pkt_buffer_t *pkt)
{
	avp_node_t *avp_apn_wildcard = NULL;
	avp_node_t *avp, *node_avp;
	uint8_t *avp_data, *avp_end;
	int i, delta = 0, global_delta = 0;

	/* Phase0: Cascade insert/replace MIP6-Agent-Info */
	for (i = 0; i < DIAMETER_MAX_APN_PARSED && avps[i].data; i++) {
		avp = &avps[i];
		avp_end = (uint8_t *)avp->avph + DIAMETER_GET_ULONG(avp->avph->avp_len);

		/* Skip wildcard APN which doesnt support MIP6-Agent-Info */
		avp_data = avp_get(AC_3GPP_SERVICE_SELECTION, avp->data, avp_end);
		if (avp_data && avp_service_selection_is_wildcard(avp_data)) {
			avp_apn_wildcard = avp;
			continue;
		}

		node_avp = avp_parse_path(ctx->avp_w1, avp_mip6_agent_info_path, avp->data, avp_end);
		if (!node_avp) {
			/* Tail insert */
			delta = avp_mip6_agent_info_insert(avp, mip, mip_len, pkt);
			pkt_buffer_put_end(pkt, delta);

			goto avps_update;
		}

		/* Update PDN-GW-Allocation-Type */
		avp_data = avp_get(AC_3GPP_PDN_GW_ALLOC_TYPE, avp->data, avp_end);
		if (avp_data)
			avp_pdn_gw_alloc_type_set(avp_data, 0);

		/* Replace current MIP-Home-Agent-Host */
		delta = avp_mip6_agent_info_replace(&node_avp[0], mip, mip_len, pkt);
		pkt_buffer_put_end(pkt, delta);

  avps_update:
		/* Update AVPs buffer offset */
		avp_buffer_offset_update(avps, i, delta);
		global_delta += delta;
	}

	/* Phase1: Wildcard APN handling */
	if (avp_apn_wildcard) {
		global_delta += apn_configuration_append(ctx->avp_w1, avps, avp_apn_wildcard, mip, pkt);

		/* Delete Specific-APN-Info */
		global_delta += avp_specific_apn_info_delete(avp_apn_wildcard, pkt);
	}

	return global_delta;
}


/*
 *	MIP Agent Host constructor
 */
static size_t
avp_str_append(uint32_t code, uint8_t *buffer, const char *str, size_t size)
{
	avp_hdr_t *avph;
	uint8_t *data;
	size_t len = size;

	avph = (avp_hdr_t *) buffer;
	avph->avp_code = htonl(code);
	data = (uint8_t *) (buffer + sizeof(*avph));
	memcpy(data, str, len);
	len += sizeof(*avph);
	avph->avp_len = htonl(len) | AVP_FL_MANDATORY;

	return len;
}

static int
avp_build_mip_home_agent_host(const char *dst_host, size_t hsize, const char *dst_realm, size_t rsize,
			      uint8_t *buffer, size_t buffer_size)
{
	uint8_t *cp = buffer;
	avp_hdr_t *avph;
	int offset = 0;
	size_t len;

	memset(buffer, 0, buffer_size);
	avph = (avp_hdr_t *) cp;
	avph->avp_code = htonl(AC_3GPP_MIP_HOME_AGENT_HOST);
	avph->avp_len = 0;
	offset += sizeof(*avph);

	len = avp_str_append(AC_3GPP_DESTINATION_HOST, buffer + offset, dst_host, hsize);
	offset += PAD4(len);

	if (rsize) {
		len = avp_str_append(AC_3GPP_DESTINATION_REALM, buffer + offset, dst_realm, rsize);
		offset += PAD4(len);
	}

	avph->avp_len = htonl(offset) | AVP_FL_MANDATORY;

	return offset;
}

int
avp_build_mip6_agent_info(dra_mip6_agent_info_t *mip)
{
	uint8_t *cp = mip->agent;
	avp_hdr_t *avph;
	int offset = 0;
	size_t len;

	avph = (avp_hdr_t *) cp;
	avph->avp_code = htonl(AC_3GPP_MIP6_AGENT_INFO);
	avph->avp_len = 0;
	offset += sizeof(*avph);

	len = avp_build_mip_home_agent_host(mip->destination_host, strlen(mip->destination_host),
					    mip->destination_realm, strlen(mip->destination_realm),
					    cp + offset, MIP_AVP_BUFSIZE - offset);
	offset += len;

	avph->avp_len = htonl(offset) | AVP_FL_MANDATORY;

	mip->agent_len = offset;
	return 0;
}

int
avp_build_mip6_agent_info_dynamic(avp_ctx_t *ctx, dra_mip6_agent_info_t *mip, pkt_buffer_t *pkt)
{
	uint8_t *cp = ctx->avp_mai;
	uint8_t *avp_origin_realm = NULL;
	char *avp_origin_realm_data = NULL;
	avp_hdr_t *avph;
	int offset = 0, avp_origin_realm_len = 0;
	size_t len;

	if (!__test_bit(MIP_FL_STATIC_HOST_BIT, &mip->flags))
		return -1;

	if (__test_bit(MIP_FL_DYNAMIC_REALM_ORIGIN_BIT, &mip->flags)) {
		avp_origin_realm = avp_get(AC_3GPP_ORIGIN_REALM, pkt->head+sizeof(msg_hdr_t), pkt->end);
		if (!avp_origin_realm)
			return -1;

		avph = (avp_hdr_t *) avp_origin_realm;
		avp_origin_realm_data = (char *)avp_origin_realm + sizeof(avp_hdr_t);
		avp_origin_realm_len = DIAMETER_GET_ULONG(avph->avp_len) - sizeof(avp_hdr_t);
	}

	avph = (avp_hdr_t *) cp;
	avph->avp_code = htonl(AC_3GPP_MIP6_AGENT_INFO);
	avph->avp_len = 0;
	offset += sizeof(*avph);

	len = avp_build_mip_home_agent_host(mip->destination_host, strlen(mip->destination_host),
					    avp_origin_realm_data, avp_origin_realm_len,
					    cp + offset, MIP_AVP_BUFSIZE - offset);
	offset += len;

	avph->avp_len = htonl(offset) | AVP_FL_MANDATORY;

	ctx->avp_mai_len = offset;
	return 0;
}


/*
 *	Diameter Context related
 */
avp_ctx_t *
avp_ctx_alloc(void)
{
	avp_ctx_t *ctx;
	msg_root_t *root;

	PMALLOC(ctx);
	PMALLOC(root);
	root->avp = MALLOC(sizeof(avp_node_t) * DIAMETER_MAX_AVP_PARSED);
	ctx->root = root;
	ctx->avp_w0 = MALLOC(sizeof(avp_node_t) * DIAMETER_MAX_APN_PARSED);
	ctx->avp_w1 = MALLOC(sizeof(avp_node_t) * DIAMETER_MAX_APN_PARSED);
	ctx->avp_w2 = MALLOC(sizeof(avp_node_t) * DIAMETER_MAX_APN_PARSED);

	return ctx;
}

void
avp_ctx_destroy(avp_ctx_t *ctx)
{
	if (!ctx)
		return;

	FREE(ctx->root->avp);
	FREE(ctx->root);
	FREE(ctx->avp_w0);
	FREE(ctx->avp_w1);
	FREE(ctx->avp_w2);
	FREE(ctx);
}
