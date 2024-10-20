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

#ifndef _DRA_JSON_H
#define _DRA_JSON_H

/* Default values */
#define DRA_JSON_THREAD_CNT_DEFAULT	5
#define DRA_JSON_BUFFER_SIZE		4096

/* Channel definition */
#define DRA_JSON_TCP_TIMEOUT        (1 * TIMER_HZ)
#define DRA_JSON_TCP_LISTENER_TIMER (1 * TIMER_HZ)
#define DRA_JSON_TCP_TIMER          (1 * TIMER_HZ)

/* Defines */
#define DRA_JSON_TIMER		(3 * TIMER_HZ)

/* session flags */
enum session_flags {
	DRA_JSON_FL_RUNNING,
};

/* Resquest channel */
typedef struct _dra_json_worker {
	int			id;
	pthread_t		task;
	int			fd;
	struct _dra_json_channel *channel;	/* backpointer */

	/* I/O MUX related */
	thread_master_t		*master;
	thread_ref_t		r_thread;

	list_head_t		next;

	unsigned long		flags;
} dra_json_worker_t;

typedef struct _dra_json_channel {
	struct sockaddr_storage	addr;
	int			thread_cnt;

	pthread_mutex_t		workers_mutex;
	list_head_t		workers;

	unsigned long		flags;
} dra_json_channel_t;

typedef struct _dra_json_session {
	pthread_t		task;
	pthread_attr_t		task_attr;
	struct sockaddr_storage	addr;
	int                     fd;
	FILE			*fp;
	uint32_t                id;

	dra_json_worker_t	*worker;

	json_writer_t		*jwriter;

	off_t			offset_read;
	off_t			offset_sent;
	char			buffer_in[DRA_JSON_BUFFER_SIZE];

	unsigned long		flags;
} dra_json_session_t;


/* Prototypes */
extern int dra_json_worker_start(void);
extern int dra_json_init(void);
extern int dra_json_destroy(void);

#endif
