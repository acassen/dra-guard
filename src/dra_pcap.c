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
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <errno.h>

/* local includes */
#include "dra_guard.h"
#include "dra_pcap.h"


/* Extern data */
extern data_t *daemon_data;


static int
dra_pcap_pkt_prepare(unsigned char *buffer, size_t len, int id)
{
	uint32_t *encap_type = (uint32_t *) buffer;
	struct iphdr *iph = (struct iphdr *) (buffer + sizeof(uint32_t));
	struct tcphdr *tcph = (struct tcphdr *) (buffer + sizeof(uint32_t) + sizeof(struct iphdr));
	int offset = sizeof(uint32_t) + sizeof(struct iphdr) + sizeof(struct tcphdr);

	/* PCAP encap type*/
	*encap_type = htonl(AF_INET);

	/* IP header */
	iph->ihl = sizeof(struct iphdr) >> 2;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(len + sizeof(struct iphdr) + sizeof(struct tcphdr));
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->saddr = htonl(id);
	iph->daddr = htonl(id);
	iph->check = 0;
	iph->check = in_csum((uint16_t *) iph, sizeof(struct iphdr), 0);

	/* TCP header */
	tcph->source = htons(DIAMETER_PORT);
	tcph->dest = htons(DIAMETER_PORT);
	tcph->doff = 5;
	tcph->window = htons(1 << 13);

	return offset;
}

void
dra_pcap_pkt_write(dra_pcap_t *p, pkt_buffer_t *pkt, int id)
{
	struct pcap_pkthdr hdr;
	int offset;

	if (!__test_bit(DRA_PCAP_FL_OPEN_BIT, &p->flags))
		return;

	pthread_mutex_lock(&p->mutex);

	offset = dra_pcap_pkt_prepare(p->buffer, pkt_buffer_len(pkt), id);

	gettimeofday(&hdr.ts, NULL);
	hdr.len = hdr.caplen = pkt_buffer_len(pkt) + offset;

	memcpy(p->buffer + offset, pkt->head, pkt_buffer_len(pkt));
	pcap_dump((u_char *)p->dumper, &hdr, p->buffer);
	pcap_dump_flush(p->dumper);

	pthread_mutex_unlock(&p->mutex);
}

pcap_dumper_t *
dra_pcap_open(dra_pcap_t *p)
{
	struct tm tmp;
	time_t now;
	char datetime_str[64];

	now = time(NULL);
        memset(&tmp, 0, sizeof(struct tm));
        tmp.tm_isdst = -1;
        localtime_r(&now, &tmp);
	strftime(datetime_str, 64, "%Y%m%d%H%M%S", &tmp);
	snprintf(p->path, DRA_PCAP_PATH, "%s-%s.pcapng", p->filename, datetime_str);

	p->pcap = pcap_open_dead(DLT_LOOP, 1 << 16);
	return pcap_dump_open(p->pcap, p->path);
}

dra_pcap_t *
dra_pcap_alloc(const char *filename)
{
	dra_pcap_t *p;

	PMALLOC(p);
	strlcpy(p->filename, filename, DRA_PCAP_FILESIZE);
	p->dumper = dra_pcap_open(p);
	if (!p->dumper) {
		log_message(LOG_INFO, "%s(): Unable to open pcap file:%s (%s)"
				    , __FUNCTION__, filename, pcap_geterr(p->pcap));
		FREE(p);
		return NULL;
	}

	pthread_mutex_init(&p->mutex, NULL);
	__set_bit(DRA_PCAP_FL_OPEN_BIT, &p->flags);
	return p;
}

void
dra_pcap_destroy(dra_pcap_t *p)
{
	if (!p)
		return;

	if (__test_bit(DRA_PCAP_FL_OPEN_BIT, &p->flags))
		pcap_dump_close(p->dumper);
	FREE(p);
}
