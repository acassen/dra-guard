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
#include <errno.h>

/* local includes */
#include "dra_guard.h"

/* Local data */
pthread_mutex_t dra_arp_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Extern data */
extern data_t *daemon_data;


/*
 *	ARP Utilities
 */
static dra_arp_t *
dra_arp_get(int ifindex, uint32_t ip_address)
{
	list_head_t *l = &daemon_data->arp_listeners;
	dra_arp_t *arp;

	pthread_mutex_lock(&dra_arp_mutex);
	list_for_each_entry(arp, l, next) {
		if (arp->ifindex == ifindex && arp->ip_address == ip_address) {
			pthread_mutex_unlock(&dra_arp_mutex);
			return arp;
		}
	}
	pthread_mutex_unlock(&dra_arp_mutex);

	return NULL;
}

static int
dra_arp_add(dra_arp_t *arp)
{
	pthread_mutex_lock(&dra_arp_mutex);
	list_add_tail(&arp->next, &daemon_data->arp_listeners);
	pthread_mutex_unlock(&dra_arp_mutex);
	return 0;
}

static int
__dra_arp_del(dra_arp_t *arp)
{
	list_head_del(&arp->next);
	return 0;
}


/*
 *	ARP related
 */
static int
dra_arp_socket_init(dra_arp_t *arp)
{
	struct sockaddr_ll sll;
	int fd, ret;

	/* ARP channel init */
	memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family = PF_PACKET;
	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_ifindex = arp->ifindex;

	fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ARP));
	if (fd < 0) {
		log_message(LOG_INFO, "%s(): Error creating ARP channel on interface %s (%m)"
				    , __FUNCTION__
				    , arp->ifname);
		return -1;
	}

	ret = bind(fd, (struct sockaddr *) &sll, sizeof(sll));
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): Error binding ARP channel on interface %s (%m)"
				    , __FUNCTION__
				    , arp->ifname);
		close(fd);
		return -1;
	}

	fd = if_setsockopt_rcvtimeo(fd, 1000);
	fd = (fd < 0) ? fd : if_setsockopt_sndtimeo(fd, 1000);
	if (fd < 0)
		return -1;

	return fd;
}

static int
dra_arp_request_handle(dra_arp_t *arp, char *buffer, size_t size)
{
	struct ethhdr *eth = (struct ethhdr *) buffer;
	arphdr_eth_t *arph = (arphdr_eth_t *) (buffer + sizeof(struct ethhdr));

	if (ntohs(eth->h_proto) != ETH_P_ARP)
		return -1;

	if (ntohs(arph->ar_op) != ARPOP_REQUEST)
		return -1;

	if (arph->ar_tip != arp->ip_address)
		return -1;

	/* Update Ethernet header */
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, arp->hwaddr, ETH_ALEN);

	/* Update ARP header */
	arph->ar_op = htons(ARPOP_REPLY);
	memcpy(arph->ar_tha, arph->ar_sha, ETH_ALEN);
	arph->ar_tip = arph->ar_sip;
	memcpy(arph->ar_sha, arp->hwaddr, ETH_ALEN);
	arph->ar_sip = arp->ip_address;
	return 0;
}


static void *
dra_arp_worker_task(void *arg)
{
	dra_arp_t *arp = arg;
	char pname[128];
	ssize_t nbytes;
	int fd, err;

	/* Our identity */
	snprintf(pname, 127, "arp-%s-%u.%u.%u.%u"
		      , arp->ifname
		      , NIPQUAD(arp->ip_address));
	prctl(PR_SET_NAME, pname, 0, 0, 0, 0);

	/* Socket init */
	fd = dra_arp_socket_init(arp);
	if (fd < 0)
		return NULL;

	signal_noignore_sig(SIGUSR1);
	log_message(LOG_INFO, "%s(): Starting arp-reply on %s for %u.%u.%u.%u"
			    , __FUNCTION__, arp->ifname, NIPQUAD(arp->ip_address));

  shoot_again:
	if (__test_bit(ARP_FL_STOPPING_BIT, &arp->flags))
		goto end;

	nbytes = recvfrom(fd, arp->buffer, ARP_BUFSIZE, 0, NULL, NULL);
	if (nbytes < 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			goto shoot_again;

		log_message(LOG_INFO, "%s(): Error recv arp on interface %s for %u.%u.%u.%u(%m)"
				    , __FUNCTION__
				    , NIPQUAD(arp->ip_address)
				    , arp->ifname);
		goto end;
	}

	err = dra_arp_request_handle(arp, arp->buffer, nbytes);
	if (err)
		goto shoot_again;
	send(fd, arp->buffer, nbytes, 0);
	goto shoot_again;

  end:
	log_message(LOG_INFO, "%s(): Stopping arp-reply on %s for %u.%u.%u.%u"
			    , __FUNCTION__, arp->ifname, NIPQUAD(arp->ip_address));
	close(fd);
	return NULL;
}



/*
 *	ARP Service init
 */
int
dra_arp_start(dra_arp_t *arp)
{
	if (__test_bit(ARP_FL_RUNNING_BIT, &arp->flags))
		return -1;

	pthread_create(&arp->task, NULL, dra_arp_worker_task, arp);
	__set_bit(ARP_FL_RUNNING_BIT, &arp->flags);
	return 0;
}

dra_arp_t *
dra_arp_init(int ifindex, const char *ifname, uint32_t ip_address)
{
	dra_arp_t *arp;

	arp = dra_arp_get(ifindex, ip_address);
	if (arp) {
		errno = EEXIST;
		return NULL;
	}

	PMALLOC(arp);
	INIT_LIST_HEAD(&arp->next);
	arp->ifindex = ifindex;
	arp->ip_address = ip_address;
	strlcpy(arp->ifname, ifname, IFNAMSIZ);
	if_nametohwaddr(ifname, arp->hwaddr, ETH_ALEN);

	dra_arp_add(arp);
	return arp;
}

static int
__dra_arp_release(dra_arp_t *arp)
{
	if (!arp->task)
		return -1;
	__set_bit(ARP_FL_STOPPING_BIT, &arp->flags);
	pthread_kill(arp->task, SIGUSR1);
	pthread_join(arp->task, NULL);
	__dra_arp_del(arp);
	FREE(arp);
	return 0;
}

int
dra_arp_release(int ifindex, uint32_t ip_address)
{
	dra_arp_t *arp;

	arp = dra_arp_get(ifindex, ip_address);
	if (!arp)
		return -1;

	pthread_mutex_lock(&dra_arp_mutex);
	__dra_arp_release(arp);
	pthread_mutex_unlock(&dra_arp_mutex);
	return 0;
}

int
dra_arp_destroy(void)
{
	dra_arp_t *arp, *_arp;

	pthread_mutex_lock(&dra_arp_mutex);
	list_for_each_entry_safe(arp, _arp, &daemon_data->arp_listeners, next)
		__dra_arp_release(arp);
	pthread_mutex_unlock(&dra_arp_mutex);

	return 0;
}
