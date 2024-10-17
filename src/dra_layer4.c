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
#include <sys/stat.h>
#include <net/if.h>

/* local includes */
#include "dra_guard.h"


/*
 *	Socket helpers
 */
enum connect_result
socket_state(thread_ref_t thread, thread_func_t func)
{
	dra_sctp_assoc_t *a = THREAD_ARG(thread);
	int fd = THREAD_FD(thread);
	int status;
	socklen_t addrlen;
	timeval_t timer_min;

	/* Handle connection timeout */
        if (thread->type == THREAD_WRITE_TIMEOUT)
                return connect_timeout;

	/* Check file descriptor */
	addrlen = sizeof(status);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *) &status, &addrlen) < 0)
		return connect_error;

	/* If status = 0, SCTP connection to remote host is established.
	 * Otherwise register checker thread to handle connection in progress,
	 * and other error code until connection is established.
	 * Recompute the write timeout (or pending connection).
	 */
	if (status == 0)
		return connect_success;

	if (status == EINPROGRESS) {
		timer_min = timer_sub_now(thread->sands);
		a->egress.w_thread = thread_add_write(thread->master, func, THREAD_ARG(thread), fd,
						      -timer_long(timer_min), 0);
		return connect_in_progress;
	}

	if (status == ETIMEDOUT)
		return connect_timeout;

	/* Since the sctp_connectx() call succeeded, treat this as a
	 * failure to establish a connection. */
	return connect_fail;
}

bool
socket_connection_state(int fd, enum connect_result status, thread_ref_t thread,
			thread_func_t func, unsigned long timeout)
{
	dra_sctp_assoc_t *a = THREAD_ARG(thread);

	if (status == connect_success ||
	    status == connect_in_progress) {
		a->egress.w_thread = thread_add_write(thread->master, func, a, fd, timeout, 0);
		return false;
	}

	return true;
}
