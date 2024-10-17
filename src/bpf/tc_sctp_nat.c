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

#define KBUILD_MODNAME "tc_sctp_nat"
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include "bpf_sctp.h"


/*
 *	MAP
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1000000);
	__type(key, __be32);				/* ipaddr */
	__type(value, struct ip_nat_rule);		/* NAT rule */
} arp_ip_nat_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1000000);
	__type(key, __be32);				/* ipaddr */
	__type(value, struct ip_nat_rule);		/* NAT rule */
} ip_nat_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1000000);
	__type(key, __be32);				/* ipaddr */
	__type(value, struct ip_nat_rule);		/* NAT rule */
} sctp_ip_nat_rules SEC(".maps");


/*
 *	Checksum related
 */
static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum>>16) + (csum & 0xffff);
	sum += (sum>>16);
	return ~sum;
}

static __always_inline void ipv4_csum(void *data_start, int data_size, __u32 *csum)
{
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper(*csum);
}

__always_inline __u32 sctp_compute_crc32(void *data_start, void *data_end, int data_size)
{
	__u32 crc32 = ~(__u32) 0;
	__u32 byte0, byte1, byte2, byte3;
	__u32 result;
	__u8 *b;
	__u32 b_shift;
	__u32 c_xored_d;
	__u32 c_xored_d_8;
	__u32 crc = 0;
	int i;

	/* why i < 1024 !? to help kernel verifier */
	for (i = 0; i < 1024 && i < data_size; i++) {
		b = (__u8 *) (data_start + i);
		if (b + 1 > data_end)
			break;

		/* help kernel verifier during compilation time by
		 * explicitly split operations. Algo is present here:
		 * draft-ietf-tsvwg-sctpcsum-03.txt
		 *   c = (c>>8) ^ crc_c[(c^*b) & 0xff]
		 * => if you try to submit this to kernel verifier you will
		 * end on wonderful and cryptic following error message :
		 * "math between pkt pointer and register with unbounded min value is not allowed"
		 */
		b_shift = crc32 >> 8;
		c_xored_d = crc32 ^ (__u32)*b;
		c_xored_d_8 = (__u8) (c_xored_d & 0x000000ff);
		crc = crc_c[c_xored_d_8];
		crc32 = b_shift ^ crc;
	}

	byte0 = (crc32 & 0xff000000) >> 24;
	byte1 = (crc32 & 0x00ff0000) >>  8;
	byte2 = (crc32 & 0x0000ff00) <<  8;
	byte3 = (crc32 & 0x000000ff) << 24;
	result = byte0 | byte1 | byte2 | byte3;

	return ~result;
}

__always_inline __u32 sctp_compute_adler32(void *data_start, void *data_end, int data_size)
{
	__u32 result = 1L;
	__u32 s1 = result & 0xffff;
	__u32 s2 = (result >> 16) & 0xffff;
	__u8 *b;
	int i;

	/* why i < 1024 !? to help kernel verifier */
	for (i = 0; i < 1024 && i < data_size; i++) {
		b = (__u8 *) (data_start + i);
		if (b + 1 > data_end)
			break;

		s1 = (s1 + *b) % ADLER_BASE;
		s2 = (s2 + s1) % ADLER_BASE;
	}

	return (s2 << 16) + s1;
}


/*
 *	Generic u32 NAT
 */
static __always_inline int u32nat(__u32 *ip, struct ip_nat_rule *rule)
{
	*ip = (*ip & ~rule->netmask) | rule->addr;
	return 0;
}


/*
 *	SCTP related
 */
static __always_inline int sctp_nat(struct __sk_buff *skb, int off, int length)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct sctphdr *sctph;
	struct sctp_chunkhdr *chunkhdr;
	struct sctp_inithdr *inithdr;
	struct sctp_paramhdr *paramhdr;
	struct sctp_ipv4addr_param *ipv4param;
	int offset = off, i, crc_update = 0;
	struct ip_nat_rule *rule;
	__u32 cksum = 0;
	__u16 len;

	/* In INIT message first chunk is init */
	sctph = data + offset;
	if (sctph + 1 > data_end)
		return TC_ACT_OK;
	offset += sizeof(*sctph);

	chunkhdr = data + offset;
	if (chunkhdr + 1 > data_end)
		return TC_ACT_OK;
	offset += sizeof(*chunkhdr);

	if (!(chunkhdr->type == SCTP_CID_INIT || chunkhdr->type == SCTP_CID_INIT_ACK))
		return TC_ACT_OK;

	inithdr = data + offset;
	if (inithdr + 1 > data_end)
		return TC_ACT_OK;
	offset += sizeof(*inithdr);

	/* chunk walk max 16 params*/
	for (i = 0; i < 16; i++) {
		paramhdr = data + offset;
		if (paramhdr + 1 > data_end)
			break;

		if (bpf_ntohs(paramhdr->type) == SCTP_PARAM_IPV4_ADDRESS) {
			ipv4param = data + offset;
			if (ipv4param + 1 > data_end)
				break;

			rule = bpf_map_lookup_elem(&sctp_ip_nat_rules, &ipv4param->addr);
			if (rule) {
				u32nat(&ipv4param->addr, rule);
				crc_update++;
			}
		}

		len = bpf_ntohs(paramhdr->length);
		if (len < 4) /* Impossible since header size is part of global size */
			return TC_ACT_OK;

		/* Trick here !!! LLVM compiler optimization makes kernel verifier crazzy !
		 * by returning math error since pkt pointer is entering security validation.
		 * We are performing bitops to force compiler new register.
		 * len is forced to max 4096bytes... this should be ok :D
		 */
		offset += len & 0xfff;
	}

	if (crc_update) {
		sctph->checksum = 0;
		cksum = sctp_compute_crc32(sctph, data_end, length);
		sctph->checksum = bpf_htonl(cksum);
	}

	return TC_ACT_OK;
}

static __always_inline int ip_nat(struct iphdr *iph, struct ip_nat_rule *rule)
{
	struct ip_nat_rule *srule = NULL;
	__u32 csum = 0;

	iph->daddr = (iph->daddr & ~rule->netmask) | rule->addr;
	if (rule->type == DRA_IP_NAT_SRC_DST) {
		u32nat(&iph->saddr, rule);
	} else {
		srule = bpf_map_lookup_elem(&ip_nat_rules, &iph->saddr);
		if (srule && (srule->type == DRA_IP_NAT_SRC_DST || srule->type == DRA_IP_NAT_SRC))
			u32nat(&iph->saddr, srule);
	}
	iph->check = 0;
	ipv4_csum(iph, sizeof(struct iphdr), &csum);
	iph->check = csum;
	return 0;
}

static __always_inline int arp_nat(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ip_nat_rule *rule = NULL;
	struct ethhdr *ethh;
	int offset = sizeof(struct ethhdr);
	struct arphdr *arph;
	__u32 *ip;

	ethh = data;
	if (ethh + 1 > data_end)
		return TC_ACT_OK;

	arph = data + offset;
	if (arph + 1 > data_end)
		return TC_ACT_OK;
	offset += sizeof(struct arphdr) + ETH_ALEN;

	if (arph->ar_op != __constant_htons(ARPOP_REQUEST))
		return TC_ACT_OK;

	if (data + offset + sizeof(__u32) > data_end)
		return TC_ACT_OK;
	ip = data + offset;

	rule = bpf_map_lookup_elem(&arp_ip_nat_rules, ip);
	if (rule)
		u32nat(ip, rule);

	offset += sizeof(__u32) + ETH_ALEN;
	if (data + offset + sizeof(__u32) > data_end)
		return TC_ACT_OK;
	ip = data + offset;

	rule = bpf_map_lookup_elem(&arp_ip_nat_rules, ip);
	if (rule)
		u32nat(ip, rule);

	return TC_ACT_OK;
}


SEC("tc")
int tc_sctp_nat(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ip_nat_rule *rule;
	struct ethhdr *ethh;
	int offset = sizeof(struct ethhdr);
	struct iphdr *iph;

	if (skb->protocol == __constant_htons(ETH_P_ARP))
		return arp_nat(skb);

	if (unlikely(skb->protocol != __constant_htons(ETH_P_IP)))
		return TC_ACT_OK;

	ethh = data;
	if (ethh + 1 > data_end)
		return TC_ACT_OK;

	iph = data + offset;
	if (iph + 1 > data_end)
		return TC_ACT_OK;
	offset += sizeof(*iph);

	/*
	 *	Egress processing
	 */
	rule = bpf_map_lookup_elem(&ip_nat_rules, &iph->daddr);
	if (rule && (rule->type == DRA_IP_NAT_SRC_DST || rule->type == DRA_IP_NAT_DST))
		ip_nat(iph, rule);

	if (iph->protocol == IPPROTO_SCTP)
		return sctp_nat(skb, offset, bpf_ntohs(iph->tot_len)-sizeof(struct iphdr));

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
