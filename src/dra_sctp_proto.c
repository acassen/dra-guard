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
#include <netdb.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <netinet/sctp.h>
#include <errno.h>

/* local includes */
#include "dra_guard.h"

/* Extern data */
extern data_t *daemon_data;


/*
 *	Utilities
 */
int
sctp_assoc_str(struct sockaddr *addrs, int cnt, char *dst, size_t dsize)
{
	struct sockaddr_in *addr;
	char *cp = dst;
	int i;

	if (!addrs)
		return -1;

	for (i = 0; i < cnt && cp-dst < dsize; i++) {
		if (addrs[i].sa_family != AF_INET)
			continue;
		if (i)
			*cp++ = ',';
		addr = (struct sockaddr_in *) &addrs[i];
		inet_ntoa2(addr->sin_addr.s_addr, cp);
		cp += strlen(cp);
	}

	*cp = '\0';
	return 0;
}


/*
 *	Plugin related
 */
static int
dra_sctp_plugin_run(int hook, pkt_buffer_t *pkt, dra_sctp_worker_t *w)
{
	dra_sctp_proxy_t *p = w->proxy;
	dra_plugin_t *plugin;
	int i, action;

	for (i = 0; i < DRA_SCTP_MAX_PLUGIN && p->plugin[i].plugin; i++) {
		plugin = p->plugin[i].plugin;

		if (plugin->generic_pkt) {
			dra_sctp_proxy_plugin_get(&p->plugin[i]);
			action = (*plugin->generic_pkt) (pkt);
			dra_sctp_proxy_plugin_put(&p->plugin[i]);
			if (action == DRA_PLUGIN_ACT_DROP)
				return DRA_PLUGIN_ACT_DROP;
		}

		if (plugin->ingress_pkt_read && hook == DRA_PLUGIN_INGRESS_READ_HOOK) {
			dra_sctp_proxy_plugin_get(&p->plugin[i]);
			action = (*plugin->ingress_pkt_read) (pkt);
			dra_sctp_proxy_plugin_put(&p->plugin[i]);
			if (action == DRA_PLUGIN_ACT_DROP)
				return DRA_PLUGIN_ACT_DROP;
		}

		if (plugin->egress_pkt_read && hook == DRA_PLUGIN_EGRESS_READ_HOOK) {
			dra_sctp_proxy_plugin_get(&p->plugin[i]);
			action = (*plugin->egress_pkt_read) (pkt);
			dra_sctp_proxy_plugin_put(&p->plugin[i]);
			if (action == DRA_PLUGIN_ACT_DROP)
				return DRA_PLUGIN_ACT_DROP;
		}
	}

	return DRA_PLUGIN_ACT_PASS;
}


/*
 *	SCTP Associations
 */
int
dra_sctp_assoc_add(dra_sctp_proxy_t *p, dra_sctp_assoc_t *a)
{
	pthread_mutex_lock(&p->assocs_mutex);
	list_add_tail(&a->next, &p->assocs);
	pthread_mutex_unlock(&p->assocs_mutex);
	return 0;
}

int
dra_sctp_assoc_del(dra_sctp_proxy_t *p, dra_sctp_assoc_t *a)
{
	pthread_mutex_lock(&p->assocs_mutex);
	list_head_del(&a->next);
	pthread_mutex_unlock(&p->assocs_mutex);
	return 0;
}

static dra_sctp_assoc_t *
dra_sctp_assoc_alloc(dra_sctp_worker_t *w)
{
	dra_sctp_assoc_t *new;
	dra_sctp_peer_t *ingress, *egress;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	ingress = &new->ingress;
	egress = &new->egress;
	ingress->pkt = pkt_buffer_alloc(SCTP_PKT_BUFFER_SIZE);
	egress->pkt = pkt_buffer_alloc(SCTP_PKT_BUFFER_SIZE);
	new->worker = w;
	dra_sctp_assoc_add(w->proxy, new);

	return new;
}

static void
dra_sctp_assoc_free(dra_sctp_assoc_t *a)
{
	dra_sctp_peer_t *ingress = &a->ingress;
	dra_sctp_peer_t *egress = &a->egress;
	dra_sctp_worker_t *w = a->worker;

#if 0
	log_message(LOG_INFO, "%s(): #%d releasing association with peer [%s]"
			    , __FUNCTION__
			    , w->id
			    , a->addrs_str);
#endif

	if (a->addrs) {
		sctp_freepaddrs(a->addrs);
		a->addrs = NULL;
	}
	pkt_buffer_free(ingress->pkt);
	pkt_buffer_free(egress->pkt);

	/* Read/Write thread pending */
	thread_cancel(ingress->r_thread);
	thread_cancel(egress->r_thread);
	thread_cancel(ingress->w_thread);
	thread_cancel(egress->w_thread);

	/* Socket release */
	if (ingress->fd) {
		shutdown(ingress->fd, SHUT_RDWR);
		close(ingress->fd);
	}
	if (egress->fd) {
		shutdown(egress->fd, SHUT_RDWR);
		close(egress->fd);
	}
	dra_sctp_assoc_del(w->proxy, a);
	FREE(a);
}

static void
dra_sctp_set_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}


/*
 *	SCTP related
 */
static void dra_sctp_read(thread_ref_t);

static int
dra_sctp_assoc_nat(dra_sctp_proxy_t *p, struct sockaddr *addrs, int cnt)
{
	struct sockaddr_in *addr;
	int i;

	for (i = 0; i < cnt; i++) {
		if (addrs[i].sa_family != AF_INET)
			continue;
		addr = (struct sockaddr_in *) &addrs[i];
	
		if ((addr->sin_addr.s_addr & p->local_nat_netmask) == p->local_nat_ip_match) {
			addr->sin_addr.s_addr = (addr->sin_addr.s_addr & ~p->local_nat_netmask) | p->local_nat_ip;
			addr->sin_port = 0;
		}
	}

	return 0;
}


static ssize_t
dra_sctp_recvmsg(int fd, pkt_buffer_t *pkt, struct sctp_sndrcvinfo *sinfo, int *msg_flags)
{
	ssize_t nbytes;

	/* FIXME: Handle realloc here... */
	if (pkt_buffer_tailroom(pkt) <= 0)
		return 0;

	*msg_flags = 0;
	nbytes = sctp_recvmsg(fd, pkt->data, pkt_buffer_tailroom(pkt)
				, NULL, NULL, sinfo, msg_flags);
	if (nbytes > 0) {
		pkt_buffer_put_data(pkt, nbytes);
		pkt_buffer_put_end(pkt, nbytes);
	}

	return nbytes;
}

static ssize_t
dra_sctp_sendmsg(int fd, pkt_buffer_t *pkt, struct sctp_sndrcvinfo *sinfo)
{
	ssize_t nbytes;

	nbytes = sctp_sendmsg(fd, pkt->data, pkt_buffer_data_tailroom(pkt), NULL, 0
				, sinfo->sinfo_ppid
				, sinfo->sinfo_flags & SCTP_UNORDERED
				, sinfo->sinfo_stream, 0, 0);
	if (nbytes > 0)
		pkt_buffer_put_data(pkt, nbytes);

	return nbytes;
}

static void
dra_sctp_write(thread_ref_t thread)
{
	dra_sctp_assoc_t *a;
	dra_sctp_worker_t *w;
	dra_sctp_proxy_t *p;
	pkt_buffer_t *pkt;
	ssize_t nbytes;
	int fd;

	/* Fetch thread elements */
	fd = THREAD_FD(thread);
	a = THREAD_ARG(thread);
	w = a->worker;
	p = w->proxy;

	/* Error Handling */
	if (thread->type == THREAD_WRITE_ERROR) {
		dra_sctp_assoc_free(a);
		return;
	}

	/* Timeout handling */
	if (thread->type == THREAD_WRITE_TIMEOUT) {
		log_message(LOG_INFO, "%s(): #%d Timeout while writing data to remote peer [%s]"
				    , __FUNCTION__
				    , w->id
			    	    , p->addrs_str);
		dra_sctp_assoc_free(a);
		return;
	}

	if (thread->u.f.flags == SCTP_FL_INGRESS) {
		pkt = a->ingress.pkt;
		nbytes = dra_sctp_sendmsg(fd, pkt, &a->ingress.sinfo);
	} else {
		pkt = a->egress.pkt;
		nbytes = dra_sctp_sendmsg(fd, pkt, &a->egress.sinfo);
	}

	if (nbytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		goto next_write;

	if (nbytes <= 0) {
		dra_sctp_assoc_free(a);
		return;
	}

	if (!pkt_buffer_data_tailroom(pkt)) {
#if 0
		printf("---[ Buffer sent ]----\n");
		if (thread->u.f.flags == SCTP_FL_INGRESS)
			dump_buffer("sent-egress ", (char *) a->ingress.pkt->head, pkt_buffer_len(a->ingress.pkt));
		else
			dump_buffer("sent-ingress ", (char *) a->egress.pkt->head, pkt_buffer_len(a->egress.pkt));
#endif

		/* Complete */
		if (thread->u.f.flags == SCTP_FL_INGRESS) {
			thread_del_write(a->egress.w_thread);
			a->egress.w_thread = NULL;
			pkt_buffer_reset(a->ingress.pkt);

			a->ingress.r_thread = thread_add_read(thread->master, dra_sctp_read, a,
							      a->ingress.fd, DRA_SCTP_TIMEOUT, SCTP_FL_INGRESS);
		} else {
			thread_del_write(a->ingress.w_thread);
			a->ingress.w_thread = NULL;
			pkt_buffer_reset(a->egress.pkt);

			a->egress.r_thread = thread_add_read(thread->master, dra_sctp_read, a,
							     a->egress.fd , DRA_SCTP_TIMEOUT, SCTP_FL_EGRESS);
		}

		return;
	}

  next_write:
	if (thread->u.f.flags == SCTP_FL_INGRESS)
		a->egress.w_thread = thread_add_write(thread->master, dra_sctp_write, a, fd,
						      DRA_SCTP_TIMEOUT, SCTP_FL_INGRESS);
	else
		a->ingress.w_thread = thread_add_write(thread->master, dra_sctp_write, a, fd,
						       DRA_SCTP_TIMEOUT, SCTP_FL_EGRESS);
}

static void
dra_sctp_read(thread_ref_t thread)
{
	dra_sctp_assoc_t *a;
	dra_sctp_worker_t *w;
	dra_sctp_proxy_t *p;
	ssize_t nbytes;
	int fd, flags = 0, action;

	/* Fetch thread elements */
	fd = THREAD_FD(thread);
	a = THREAD_ARG(thread);
	w = a->worker;
	p = w->proxy;

	/* Error Handling */
	if (thread->type == THREAD_READ_ERROR) {
		dra_sctp_assoc_free(a);
		return;
	}

	/* Timeout handling */
	if (thread->type == THREAD_READ_TIMEOUT) {
		if (thread->u.f.flags == SCTP_FL_INGRESS &&
		    __test_bit(SCTP_FL_COMPLETE, &a->ingress.flags))
			goto next_read;

		if (thread->u.f.flags == SCTP_FL_EGRESS &&
		    __test_bit(SCTP_FL_COMPLETE, &a->egress.flags))
			goto next_read;

		log_message(LOG_INFO, "%s(): #%d Timeout while reading data from remote peer [%s]"
				    , __FUNCTION__
				    , w->id
				    , (thread->u.f.flags == SCTP_FL_INGRESS) ? a->addrs_str :
				    					       p->connect_addrs_str);
		dra_sctp_assoc_free(a);
		return;
	}


	if (thread->u.f.flags == SCTP_FL_INGRESS) {
		__clear_bit(SCTP_FL_COMPLETE, &a->ingress.flags);
		nbytes = dra_sctp_recvmsg(fd, a->ingress.pkt, &a->ingress.sinfo, &flags);
	} else {
		__clear_bit(SCTP_FL_COMPLETE, &a->egress.flags);
		nbytes = dra_sctp_recvmsg(fd, a->egress.pkt, &a->egress.sinfo, &flags);
	}

	if (nbytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		goto next_read;

	if (nbytes < 0) {
		log_message(LOG_INFO, "%s(): #%d sctp_recvmsg error(%m) from remote peer [%s]"
				    , __FUNCTION__
				    , w->id
				    , a->addrs_str);
		dra_sctp_assoc_free(a);
		return;
	}

	if (nbytes == 0) {
		log_message(LOG_INFO, "%s(): #%d remote peer [%s] closed connection"
				    , __FUNCTION__
				    , w->id
				    , a->addrs_str);
		dra_sctp_assoc_free(a);
		return;
	}

	/* TODO: Add support to notification handling */
	if (flags & MSG_NOTIFICATION)
		goto next_read;

	if (flags & MSG_EOR) {
#if 0
		printf("----[ Incoming buffer ]----\n");
		if (thread->u.f.flags == SCTP_FL_INGRESS)
			dump_buffer("recv-ingress ", (char *) a->ingress.pkt->head, pkt_buffer_len(a->ingress.pkt));
		else
			dump_buffer("recv-egress ", (char *) a->egress.pkt->head, pkt_buffer_len(a->egress.pkt));
#endif

		if (thread->u.f.flags == SCTP_FL_INGRESS) {
			__set_bit(SCTP_FL_COMPLETE, &a->ingress.flags);
			thread_del_read(a->ingress.r_thread);
			a->ingress.r_thread = NULL;
			pkt_buffer_reset_data(a->ingress.pkt);

			if (__test_and_clear_bit(SCTP_FL_DISCARD, &a->ingress.flags))
				goto next_read;

			action = dra_sctp_plugin_run(DRA_PLUGIN_INGRESS_READ_HOOK, a->ingress.pkt, w);
			if (action == DRA_PLUGIN_ACT_DROP)
				goto next_read;

			/* Built-in feature */
			dra_route_optimization(a->ingress.pkt, w, NULL);

			a->egress.w_thread = thread_add_write(thread->master, dra_sctp_write, a,
							      a->egress.fd, DRA_SCTP_TIMEOUT,
							      SCTP_FL_INGRESS);
		} else {
			__set_bit(SCTP_FL_COMPLETE, &a->egress.flags);
			thread_del_read(a->egress.r_thread);
			a->egress.r_thread = NULL;
			pkt_buffer_reset_data(a->egress.pkt);

			if (__test_and_clear_bit(SCTP_FL_DISCARD, &a->egress.flags))
				goto next_read;

			action = dra_sctp_plugin_run(DRA_PLUGIN_EGRESS_READ_HOOK, a->egress.pkt, w);
			if (action == DRA_PLUGIN_ACT_DROP)
				goto next_read;

			/* Built-in feature */
			dra_route_optimization(a->egress.pkt, w, NULL);

			a->ingress.w_thread = thread_add_write(thread->master, dra_sctp_write, a,
							       a->ingress.fd , DRA_SCTP_TIMEOUT,
							       SCTP_FL_EGRESS);
		}

		return;
	}

	/* pkt full and no MSG_EOR means need more room ! discard pkt too big... */
	if (thread->u.f.flags == SCTP_FL_INGRESS) {
		__set_bit(SCTP_FL_DISCARD, &a->ingress.flags);
		pkt_buffer_reset_data(a->ingress.pkt);
	} else {
		__set_bit(SCTP_FL_DISCARD, &a->egress.flags);
		pkt_buffer_reset_data(a->egress.pkt);
	}

	log_message(LOG_INFO, "%s(): #%d %s pkt need more room for remote peer [%s] discarding..."
				, __FUNCTION__
				, w->id
				, (thread->u.f.flags == SCTP_FL_INGRESS) ? "ingress" : "egress"
				, a->addrs_str);

  next_read:
	if (thread->u.f.flags == SCTP_FL_INGRESS)
		a->ingress.r_thread = thread_add_read(thread->master, dra_sctp_read, a, fd,
						      DRA_SCTP_TIMEOUT, SCTP_FL_INGRESS);
	else
		a->egress.r_thread = thread_add_read(thread->master, dra_sctp_read, a, fd,
						     DRA_SCTP_TIMEOUT, SCTP_FL_EGRESS);
}

static void
sctp_check_thread(thread_ref_t thread)
{
	dra_sctp_assoc_t *a = THREAD_ARG(thread);
	dra_sctp_worker_t *w = a->worker;
	dra_sctp_proxy_t *p = w->proxy;
	int status;

	/* unsubscribe from I/O MUX */
	thread_del_write(a->egress.w_thread);
	a->egress.w_thread = NULL;

	status = socket_state(thread, sctp_check_thread);

	/* If status = connect_in_progress, next thread is already registered.
	 * If it is connect_success, the fd is still open.
	 * Otherwise we have a real connection error or connection timeout.
	 */
	switch(status) {
	case connect_in_progress:
		break;
	case connect_success:
		log_message(LOG_INFO, "%s(): Success connecting [%s]<->[%s]"
					, __FUNCTION__
					, a->addrs_str, p->addrs_str);
		__set_bit(SCTP_FL_CONNECTED, &a->egress.flags);

		/* Next-Step: receive data from ingress & egress */
		a->ingress.r_thread = thread_add_read(thread->master, dra_sctp_read, a,
						      a->ingress.fd, DRA_SCTP_LISTENER_TIMER,
						      SCTP_FL_INGRESS);

		a->egress.r_thread = thread_add_read(thread->master, dra_sctp_read, a,
						     a->egress.fd, DRA_SCTP_LISTENER_TIMER,
						     SCTP_FL_EGRESS);
		break;
	case connect_timeout:
		log_message(LOG_INFO, "%s(): Timeout connecting to egress [%s]"
					, __FUNCTION__
					, p->addrs_str);
		dra_sctp_assoc_free(a);
		break;
	default:
		log_message(LOG_INFO, "%s(): Error connecting to egress [%s]"
					, __FUNCTION__
					, p->addrs_str);
		dra_sctp_assoc_free(a);
	}
}

static void
dra_sctp_connect(thread_ref_t thread)
{
	dra_sctp_worker_t *w;
	dra_sctp_proxy_t *p;
	dra_sctp_assoc_t *a;
	dra_sctp_peer_t *ingress, *egress;
	struct sctp_status status;
//	struct sctp_event_subscribe events;
	enum connect_result sctp_status = connect_error;
	int err, fd;

	/* Fetch thread elements */
	a = THREAD_ARG(thread);
	w = a->worker;
	p = w->proxy;
	ingress = &a->ingress;
	egress = &a->egress;

	/* Get number of streams */
	err = if_getsockopt_sctp_status(ingress->fd, &status);
	if (err) {
		log_message(LOG_INFO, "%s(): #%d Error getting sctp_status from Peer [%s] (%m)"
				, __FUNCTION__
				, w->id
				, a->addrs_str);
		dra_sctp_assoc_free(a);
		return;
	}

	/* egress connection */
	fd = socket(AF_INET, SOCK_STREAM | O_NONBLOCK, IPPROTO_SCTP);
	fd = (fd < 0) ? fd : if_setsockopt_reuseaddr(fd, 1);
	fd = (fd < 0) ? fd : if_setsockopt_nolinger(fd, 1);
	fd = (fd < 0) ? fd : if_setsockopt_sctp_nodelay(fd, 1);
	if (fd < 0) {
		log_message(LOG_INFO, "%s(): error creating egress socket for peer [%s] (%m)"
				    , __FUNCTION__
				    , a->addrs_str);
		dra_sctp_assoc_free(a);
		return;
	}
	egress->fd = fd;

	/* Transitive setting for egress SCTP associations */
	egress->initmsg.sinit_num_ostreams = status.sstat_instrms;
	egress->initmsg.sinit_max_instreams = status.sstat_outstrms;
	err = if_setsockopt_sctp_initmsg(fd, &egress->initmsg);
	if (err < 0) {
		log_message(LOG_INFO, "%s(): error setting egress sctp_initmsg for peer [%s]"
				    , __FUNCTION__
				    , a->addrs_str);
		dra_sctp_assoc_free(a);
		return;
	}

#if 0
	/* SCTP I/O event subscribe */
	memset(&events, 0, sizeof(struct sctp_event_subscribe));
	events.sctp_data_io_event = 1;
	events.sctp_association_event = 1;
	events.sctp_shutdown_event = 1;
	err = if_setsockopt_sctp_events(fd, &events);
	if (err < 0) {
		log_message(LOG_INFO, "%s(): error subscribing egress to I/O events for peer [%s]"
				    , __FUNCTION__
				    , a->addrs_str);
		dra_sctp_assoc_free(a);
		return;
	}
#endif

	/* NAT if in use */
	if (__test_bit(SCTP_FL_LOCAL_NAT, &p->flags))
		dra_sctp_assoc_nat(p, a->addrs, a->addrs_cnt);

	/* Bind to local */
	err = sctp_bindx(fd, a->addrs, a->addrs_cnt, SCTP_BINDX_ADD_ADDR);
	if (err) {
		dra_sctp_assoc_free(a);
		return;
	}

	/* async non-block connect */
	err = sctp_connectx(fd, p->connect_addrs, p->connect_addrs_cnt, NULL);
	if (err) {
		if (errno != EINPROGRESS) {
			log_message(LOG_INFO, "%s(): error connecting egress to [%s] (%m)"
					    , __FUNCTION__
					    , a->addrs_str);
			dra_sctp_assoc_free(a);
			return;
		}

		sctp_status = connect_in_progress;
	} else {
		/* unlikely: Direct connection success */
		sctp_status = connect_success;
	}

	if (socket_connection_state(fd, sctp_status, thread, sctp_check_thread, DRA_SCTP_TIMEOUT)) {
		/* connect_error or connect_failt */
		dra_sctp_assoc_free(a);
        }
}

static void
dra_sctp_accept(thread_ref_t thread)
{
	dra_sctp_worker_t *w;
	dra_sctp_proxy_t *p;
	dra_sctp_assoc_t *a;
	dra_sctp_peer_t *peer;
	int fd, accept_fd, ret;

	/* Fetch thread elements */
	fd = THREAD_FD(thread);
	w = THREAD_ARG(thread);
	p = w->proxy;

	/* Terminate event */
	if (__test_bit(SCTP_FL_STOP, &p->flags)) {
		thread_del_read(w->r_thread);
		close(fd);
		thread_add_terminate_event(thread->master);
		return;
	}

	/* Wait until accept event */
	if (thread->type == THREAD_READ_TIMEOUT)
		goto next_accept;

	/* Accept incoming connection */
	accept_fd = accept(fd, NULL, NULL);
	if (accept_fd < 0) {
		log_message(LOG_INFO, "%s(): #%d Error accepting connection on '%s' (%m)"
				    , __FUNCTION__, w->id, p->name);
                goto next_accept;
        }

	ret = if_setsockopt_sctp_nodelay(accept_fd, 1);
	ret = (ret < 0) ? ret : if_setsockopt_nolinger(accept_fd, 1);
	if (ret < 0)
		goto next_accept;

	/* SCTP association allocation */
	a = dra_sctp_assoc_alloc(w);
	peer = &a->ingress;
	peer->fd = accept_fd;
	dra_sctp_set_nonblock(peer->fd); /* socket flags inherit is working ? */
	__set_bit(SCTP_FL_CONNECTED, &a->ingress.flags);

	/* Get peer addresses */
	ret = sctp_getpaddrs(peer->fd, -1, &a->addrs);
	if (ret < 0) {
		log_message(LOG_INFO, "%s(): #%d Couldnt retreive peer addresses on '%s' (%m)"
				    , __FUNCTION__, w->id, p->name);
		dra_sctp_assoc_free(a);
		goto next_accept;
	}

	a->addrs_cnt = ret;
	sctp_assoc_str(a->addrs, a->addrs_cnt, a->addrs_str, DRA_STR_MAX_LEN);
	thread_add_event(thread->master, dra_sctp_connect, a, 0);

  next_accept:
        /* Register read thread on listen fd */
        w->r_thread = thread_add_read(thread->master, dra_sctp_accept, w, fd
						    , DRA_SCTP_LISTENER_TIMER, 0);
}


static int
dra_sctp_listen(dra_sctp_worker_t *w)
{
	mode_t old_mask;
	dra_sctp_proxy_t *p = w->proxy;
//	struct sctp_event_subscribe events;
        int err, fd = -1;

	/* Mask */
	old_mask = umask(0077);

	/* Create socket */
	fd = socket(AF_INET, SOCK_STREAM | O_NONBLOCK, IPPROTO_SCTP);
	fd = (fd < 0) ? fd : if_setsockopt_reuseaddr(fd, 1);
	fd = (fd < 0) ? fd : if_setsockopt_reuseport(fd, 1); /* ingress loadbalancing */
	if (fd < 0) {
		log_message(LOG_INFO, "%s(): error creating listening socket for %s"
				    , __FUNCTION__
				    , p->name);
		return -1;
	}

	/* SCTP Initmsg*/
	err = if_setsockopt_sctp_initmsg(fd, &p->server_initmsg);
	if (err < 0)
		return -1;

#if 0
	/* SCTP I/O event subscribe */
	memset(&events, 0, sizeof(struct sctp_event_subscribe));
	events.sctp_data_io_event = 1;
	err = if_setsockopt_sctp_events(fd, &events);
	if (err < 0)
		return -1;
#endif

	/* Bind listening channel */
	err = sctp_bindx(fd, p->addrs, p->addrs_cnt, SCTP_BINDX_ADD_ADDR);
	if (err) {
		log_message(LOG_INFO, "%s(): Cant bind '%s' listening socket (%m)"
				    , __FUNCTION__, p->name);
		goto error;
	}

	/* Init listening channel */
	err = listen(fd, 10);
	if (err < 0) {
		log_message(LOG_INFO, "%s(): Error listening on '%s' socket (%m)"
				    , __FUNCTION__
                                    , p->name);
                goto error;
        }

        /* Restore old mask */
        umask(old_mask);

        /* Register acceptor thread */
        w->fd = fd;
        w->r_thread = thread_add_read(w->master, dra_sctp_accept, w, fd, DRA_SCTP_LISTENER_TIMER, 0);
        return fd;

  error:
        close(fd);
        return -1;
}


/*
 *	SCTP Task
 */
static void *
dra_sctp_worker_task(void *arg)
{
	dra_sctp_worker_t *w = arg;
	dra_sctp_proxy_t *p = w->proxy;
	char pname[128];

	/* Create Process Name */
	snprintf(pname, 127, "sctp-%s-%d", p->name, w->id);
	prctl(PR_SET_NAME, pname, 0, 0, 0, 0);

	signal_noignore_sig(SIGUSR1);

	/* Welcome message */
	log_message(LOG_INFO, "%s(): Starting Proxy Server[%s]/Worker[%d]"
			    , __FUNCTION__
			    , p->name
			    , w->id);
	__set_bit(SCTP_FL_RUNNING, &w->flags);

	/* I/O MUX init */
	w->master = thread_make_master(true);

	/* Register listener */
	dra_sctp_listen(w);

	/* Infinite loop */
	launch_thread_scheduler(w->master);

	/* Release Master stuff */
	log_message(LOG_INFO, "%s(): Stopping Proxy Server[%s]/Worker[%d]"
			    , __FUNCTION__
			    , p->name
			    , w->id);
	__clear_bit(SCTP_FL_RUNNING, &w->flags);
//	thread_destroy_master(w->master);
	return NULL;
}


/*
 *	SCTP Workers related
 */
static int
dra_sctp_worker_launch(dra_sctp_proxy_t *p)
{
	dra_sctp_worker_t *w;

	pthread_mutex_lock(&p->workers_mutex);
	list_for_each_entry(w, &p->workers, next) {
		pthread_create(&w->task, NULL, dra_sctp_worker_task, w);
	}
	pthread_mutex_unlock(&p->workers_mutex);

	return 0;
}

int
dra_sctp_worker_start(dra_sctp_proxy_t *p)
{
	if (!__test_bit(SCTP_FL_RUNNING, &p->flags))
	    return -1;

	return dra_sctp_worker_launch(p);
}

static int
dra_sctp_worker_alloc(dra_sctp_proxy_t *p, int id)
{
	dra_sctp_worker_t *w;

	PMALLOC(w);
	INIT_LIST_HEAD(&w->next);
	w->avp_ctx = avp_ctx_alloc();
	w->id = id;
	w->proxy = p;

	pthread_mutex_lock(&p->workers_mutex);
	list_add_tail(&w->next, &p->workers);
	pthread_mutex_unlock(&p->workers_mutex);

	return 0;
}

static void
dra_sctp_worker_release(dra_sctp_worker_t *w)
{
	avp_ctx_destroy(w->avp_ctx);
	list_head_del(&w->next);
	FREE(w);
}


/*
 *	SCTP Proto related
 */
int
dra_sctp_proto_init(dra_sctp_proxy_t *p)
{
	int i;

	/* Init worker related */
	INIT_LIST_HEAD(&p->workers);
	INIT_LIST_HEAD(&p->assocs);
	for (i = 0; i < p->thread_cnt; i++)
		dra_sctp_worker_alloc(p, i);

	__set_bit(SCTP_FL_RUNNING, &p->flags);
	return 0;
}

int
dra_sctp_proto_destroy(dra_sctp_proxy_t *p)
{
	dra_sctp_worker_t *w, *_w;

	if (!__test_bit(SCTP_FL_RUNNING, &p->flags))
		return -1;

	__set_bit(SCTP_FL_STOP, &p->flags);

	pthread_mutex_lock(&p->workers_mutex);
	list_for_each_entry_safe(w, _w, &p->workers, next) {
		pthread_kill(w->task, SIGUSR1);
		pthread_join(w->task, NULL);
		dra_sctp_worker_release(w);
	}
	pthread_mutex_unlock(&p->workers_mutex);
	return 0;
}
