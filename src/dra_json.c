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
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

/* local includes */
#include "dra_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	Handle request
 */
static bool
dra_json_msisdn_isvalid(const char *msisdn)
{
	const char *cp;

	for (cp = msisdn; *cp; cp++) {
		if (!isdigit((int) *cp)) {
			return false;
		}
	}

	return true;
}

static int
dra_json_json_parse_cmd(dra_json_session_t *s, json_node_t *json)
{
	char *cmd_str = NULL, *msisdn_str = NULL, *profile_str = NULL;
	dra_debug_entry_t *e = NULL;
	dra_mip6_agent_info_t *mip;
	uint64_t msisdn;
	int err;

	jsonw_start_object(s->jwriter);

	if (!json_find_member_strvalue(json, "cmd", &cmd_str)) {
		jsonw_string_field(s->jwriter, "Error", "No command specified");
		goto end;
	}

	if (!strncmp(cmd_str, "msisdn_lst", 10)) {
		dra_debug_json(s->jwriter, &daemon_data->debug_target);
		jsonw_end_object(s->jwriter);
		return 0;
	}

	if (!json_find_member_strvalue(json, "msisdn", &msisdn_str)) {
		jsonw_string_field(s->jwriter, "Error", "No MSISDN specified");
		goto end;
	}

	if (!dra_json_msisdn_isvalid(msisdn_str)) {
		jsonw_string_field(s->jwriter, "Error", "malformed MSISDN");
		goto end;
	}

	msisdn = strtoul(msisdn_str, NULL, 10);
	if (!strncmp(cmd_str, "msisdn_add", 10)) {
		if (!json_find_member_strvalue(json, "profile", &profile_str)) {
			jsonw_string_field(s->jwriter, "Error", "No Profile specified");
			goto end;
		}

		if (!profile_str) {
			jsonw_string_field(s->jwriter, "Error", "no profile specified");
			goto end;
		}

		mip = dra_mip_get(profile_str);
		if (!mip) {
			jsonw_string_field_fmt(s->jwriter, "Error", "unknown profile %s"
							 , profile_str);
			goto end;
		}

		e = dra_debug_entry_get(&daemon_data->debug_target, msisdn);
		if (e) {
			jsonw_string_field_fmt(s->jwriter, "Error", "MSISDN %ld already configured"
							 , msisdn);
			dra_debug_entry_put(e);
			goto end;
		}

		e = dra_debug_entry_alloc(&daemon_data->debug_target, msisdn);
		e->mip = mip;
		__set_bit(DRA_DEBUG_FL_JSON, &e->flags);
		dra_debug_entry_put(e);

		jsonw_string_field_fmt(s->jwriter, "Success", "MSISDN %ld successfully added"
						 , msisdn);
		goto end;
	}

	if (!strncmp(cmd_str, "msisdn_del", 10)) {
		err = dra_debug_entry_destroy(&daemon_data->debug_target, msisdn);
		if (err) {
			jsonw_string_field_fmt(s->jwriter, "Error", "unknown MSISDN %ld"
							 , msisdn);
			goto end;
		}

		jsonw_string_field_fmt(s->jwriter, "Success", "MSISDN %ld successfully removed"
						 , msisdn);
	}

  end:
	jsonw_end_object(s->jwriter);

	/* Not really optimal stuff, but no performances here are needed */
	if (__test_bit(DRA_FL_JSON_STORE_BIT, &daemon_data->flags))
		dra_debug_disk_write_entries(&daemon_data->debug_target, daemon_data->json_store);
	return 0;
}

static int
dra_json_parse(dra_json_session_t *s)
{
	json_node_t *json;

	json = json_decode(s->buffer_in);
	if (!json) {
		log_message(LOG_INFO, "%s(): Error parsing JSON string : [%s]"
				    , __FUNCTION__
				    , s->buffer_in);
		return -1;
	}

	dra_json_json_parse_cmd(s, json);
	json_destroy(json);
	return 0;
}


/*
 *	Main TCP thread
 */
static int
dra_json_session_close(dra_json_session_t *s)
{
	jsonw_destroy(&s->jwriter);
	fclose(s->fp);	/* Also close s->fd */
	FREE(s);
	return 0;
}

int
dra_json_http_read(int sd, void *data, int size)
{
	int nbytes, offset = 0;
	char *buffer = (char *) data;

	if (!size)
		return 0;

next_rcv:
	if (__test_bit(DRA_FL_STOP_BIT, &daemon_data->flags))
		return -1;

	nbytes = read(sd, data + offset, size - offset);

	/* data are ready ? */
	if (nbytes == -1 || nbytes == 0) {
		if (nbytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
			goto next_rcv;

		return -1;
	}

	/* Everything but the girl ! */
	offset += nbytes;

	if (buffer[offset-2] == '\r' && buffer[offset-1] == '\n')
		return offset;

	if (offset < size)
		goto next_rcv;

	return size;
}

static int
dra_json_rcv(dra_json_session_t *s)
{
	char *buffer = s->buffer_in;
	int ret;

	memset(buffer, 0, DRA_JSON_BUFFER_SIZE);
	ret = dra_json_http_read(s->fd, buffer, DRA_JSON_BUFFER_SIZE);
	if (ret < 0)
		return -1;

	return ret;
}

void *
dra_json_tcp_thread(void *arg)
{
	dra_json_session_t *s = arg;
	char identity[64];
	int old_type, ret;

	/* Out identity */
	snprintf(identity, 63, "%s", inet_sockaddrtos(&s->addr));
	prctl(PR_SET_NAME, identity, 0, 0, 0, 0);

	/* Set Cancel type */
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &old_type);

	/* Set timeout on session fd */
	s->fd = if_setsockopt_rcvtimeo(s->fd, 2000);
	s->fd = if_setsockopt_sndtimeo(s->fd, 2000);
	if (s->fd < 0)
		goto end;

	ret = dra_json_rcv(s);
	if (ret < 0)
		goto end;

	/* session handle */
#if 0
	dump_buffer("JSON : ", s->buffer_in, ret);
	printf("---[%s]---\nlength:%d\n", s->buffer_in, ret);
#endif
	s->jwriter = jsonw_new(s->fp);
	jsonw_pretty(s->jwriter, true);
	dra_json_parse(s);
	jsonw_destroy(&s->jwriter);

  end:
	dra_json_session_close(s);
	return NULL;
}


/*
 *	Accept
 */
static void
dra_json_tcp_accept(thread_ref_t thread)
{
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);
	dra_json_worker_t *w;
        dra_json_session_t *s;
        int fd, accept_fd, ret;

        /* Fetch thread elements */
        fd = THREAD_FD(thread);
        w = THREAD_ARG(thread);

	/* Terminate event */
	if (__test_bit(DRA_FL_STOP_BIT, &daemon_data->flags))
		thread_add_terminate_event(thread->master);

        /* Wait until accept event */
        if (thread->type == THREAD_READ_TIMEOUT)
                goto next_accept;

        /* Accept incoming connection */
        accept_fd = accept(fd, (struct sockaddr *) &addr, &addrlen);
        if (accept_fd < 0) {
                log_message(LOG_INFO, "%s(): #%d Error accepting connection from peer [%s]:%d (%m)"
                                    , __FUNCTION__
                                    , w->id
                                    , inet_sockaddrtos(&addr)
                                    , ntohs(inet_sockaddrport(&addr)));
                goto next_accept;
        }

        /* remote client session allocation */
	PMALLOC(s);
        s->fd = accept_fd;
        s->addr = addr;
        s->worker = w;
	s->fp = fdopen(accept_fd, "w");
	if (!s->fp) {
		log_message(LOG_INFO, "%s(): #%d cant fdopen on accept socket with peer [%s]:%d (%m)"
				    , __FUNCTION__
				    , w->id
				    , inet_sockaddrtos(&addr)
				    , ntohs(inet_sockaddrport(&addr)));
		dra_json_session_close(s);
		goto next_accept;
	}

        /* Register reader on accept_sd */
        if_setsockopt_nodelay(s->fd, 1);
	if_setsockopt_nolinger(s->fd, 1);

	/* Spawn a dedicated pthread per client. Dont really need performance here,
	 * simply handle requests synchronously */
	ret = pthread_attr_init(&s->task_attr);
	if (ret != 0) {
		log_message(LOG_INFO, "%s(): #%d cant init pthread_attr for session with peer [%s]:%d (%m)"
				    , __FUNCTION__
				    , w->id
				    , inet_sockaddrtos(&addr)
				    , ntohs(inet_sockaddrport(&addr)));
		dra_json_session_close(s);
		goto next_accept;
	}

	ret = pthread_attr_setdetachstate(&s->task_attr, PTHREAD_CREATE_DETACHED);
	if (ret != 0) {
		log_message(LOG_INFO, "%s(): #%d cant set pthread detached for session with peer [%s]:%d (%m)"
				    , __FUNCTION__
				    , w->id
				    , inet_sockaddrtos(&addr)
				    , ntohs(inet_sockaddrport(&addr)));
		dra_json_session_close(s);
		goto next_accept;
	}

	ret = pthread_create(&s->task, &s->task_attr, dra_json_tcp_thread, s);
	if (ret != 0) {
		log_message(LOG_INFO, "%s(): #%d cant create pthread for session with peer [%s]:%d (%m)"
				    , __FUNCTION__
				    , w->id
				    , inet_sockaddrtos(&addr)
				    , ntohs(inet_sockaddrport(&addr)));
		dra_json_session_close(s);
	}

  next_accept:
        /* Register read thread on listen fd */
        w->r_thread = thread_add_read(thread->master, dra_json_tcp_accept, w, fd,
                                      DRA_JSON_TCP_LISTENER_TIMER, 0);
}


/*
 *	Listener
 */
static int
dra_json_tcp_listen(dra_json_worker_t *w)
{
        mode_t old_mask;
        dra_json_channel_t *req = w->channel;
        struct sockaddr_storage *addr = &req->addr;
        socklen_t addrlen;
        int err, fd = -1;

        /* Mask */
        old_mask = umask(0077);

        /* Create socket */
        fd = socket(addr->ss_family, SOCK_STREAM, 0);
        fd = (fd < 0) ? fd : if_setsockopt_reuseaddr(fd, 1);
        fd = (fd < 0) ? fd : if_setsockopt_reuseport(fd, 1);
        if (fd < 0) {
                log_message(LOG_INFO, "%s(): error creating [%s]:%d socket"
                                    , __FUNCTION__
                                    , inet_sockaddrtos(addr)
                                    , ntohs(inet_sockaddrport(addr)));
                return -1;
        }

        /* Bind listening channel */
        addrlen = (addr->ss_family == AF_INET) ? sizeof(struct sockaddr_in) :
                                                 sizeof(struct sockaddr_in6);
        err = bind(fd, (struct sockaddr *) addr, addrlen);
        if (err < 0) {
                log_message(LOG_INFO, "%s(): Error binding to [%s]:%d (%m)"
                                    , __FUNCTION__
                                    , inet_sockaddrtos(addr)
                                    , ntohs(inet_sockaddrport(addr)));
                goto error;
        }

        /* Init listening channel */
        err = listen(fd, 5);
        if (err < 0) {
                log_message(LOG_INFO, "%s(): Error listening on [%s]:%d (%m)"
                                    , __FUNCTION__
                                    , inet_sockaddrtos(addr)
                                    , ntohs(inet_sockaddrport(addr)));
                goto error;
        }

        /* Restore old mask */
        umask(old_mask);

        /* Register acceptor thread */
        w->r_thread = thread_add_read(w->master, dra_json_tcp_accept, w, fd,
                                      DRA_JSON_TCP_LISTENER_TIMER, 0);
        w->fd = fd;
        return fd;

  error:
        close(fd);
        return -1;
}

static void *
dra_json_worker_task(void *arg)
{
	dra_json_worker_t *w = arg;
	dra_json_channel_t *srv = w->channel;
	char pname[128];

	/* Create Process Name */
	snprintf(pname, 127, "json-ch-%d", w->id);
	prctl(PR_SET_NAME, pname, 0, 0, 0, 0);

        /* Welcome message */
        log_message(LOG_INFO, "%s(): Starting JSON Listener Server[%s:%d]/Worker[%d]"
                            , __FUNCTION__
                            , inet_sockaddrtos(&srv->addr)
                            , ntohs(inet_sockaddrport(&srv->addr))
                            , w->id);
	__set_bit(DRA_JSON_FL_RUNNING, &w->flags);

        /* I/O MUX init */
        w->master = thread_make_master(true);

        /* Register listener */
        dra_json_tcp_listen(w);

        /* Infinite loop */
        launch_thread_scheduler(w->master);

        /* Release Master stuff */
        log_message(LOG_INFO, "%s(): Stopping JSON Listener Server[%s:%d]/Worker[%d]"
                            , __FUNCTION__
                            , inet_sockaddrtos(&srv->addr)
                            , ntohs(inet_sockaddrport(&srv->addr))
                            , w->id);
	__clear_bit(DRA_JSON_FL_RUNNING, &w->flags);
	return NULL;
}

/*
 *	TCP listener init
 */
int
dra_json_worker_launch(dra_json_channel_t *srv)
{
	dra_json_worker_t *w;

	pthread_mutex_lock(&srv->workers_mutex);
	list_for_each_entry(w, &srv->workers, next) {
		pthread_create(&w->task, NULL, dra_json_worker_task, w);
	}
	pthread_mutex_unlock(&srv->workers_mutex);

	return 0;
}

int
dra_json_worker_start(void)
{
	dra_json_channel_t *srv = &daemon_data->json_channel;

	if (!(__test_bit(DRA_JSON_FL_RUNNING, &srv->flags)))
	    return -1;

	dra_json_worker_launch(srv);

	return 0;
}

static int
dra_json_worker_alloc(dra_json_channel_t *srv, int id)
{
	dra_json_worker_t *worker;

	PMALLOC(worker);
	INIT_LIST_HEAD(&worker->next);
	worker->channel = srv;
	worker->id = id;

	pthread_mutex_lock(&srv->workers_mutex);
	list_add_tail(&worker->next, &srv->workers);
	pthread_mutex_unlock(&srv->workers_mutex);

	return 0;
}

static int
dra_json_worker_release(dra_json_worker_t *w)
{
	thread_destroy_master(w->master);
	close(w->fd);
	return 0;
}


/*
 *	GTP Request init
 */
int
dra_json_init(void)
{
	dra_json_channel_t *srv = &daemon_data->json_channel;
	int i;

	/* Init worker related */
        INIT_LIST_HEAD(&srv->workers);
	for (i = 0; i < srv->thread_cnt; i++)
		dra_json_worker_alloc(srv, i);

	__set_bit(DRA_JSON_FL_RUNNING, &srv->flags);

	return 0;
}

int
dra_json_destroy(void)
{
	dra_json_channel_t *srv = &daemon_data->json_channel;
	dra_json_worker_t *w, *_w;

	if (!__test_bit(DRA_JSON_FL_RUNNING, &srv->flags))
		return -1;

	pthread_mutex_lock(&srv->workers_mutex);
	list_for_each_entry_safe(w, _w, &srv->workers, next) {
		pthread_join(w->task, NULL);
	        dra_json_worker_release(w);
		list_head_del(&w->next);
		FREE(w);
	}
	pthread_mutex_unlock(&srv->workers_mutex);

	return 0;
}
