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

#ifndef _TIMER_THREAD_H
#define _TIMER_THREAD_H

enum {
	TIMER_THREAD_FL_STOP_BIT,
};

#define TIMER_THREAD_NAMESIZ	128
typedef struct _timer_thread {
	char			name[TIMER_THREAD_NAMESIZ];
	rb_root_cached_t	timer;
	pthread_mutex_t		timer_mutex;
	pthread_t		task;
	pthread_cond_t		cond;
	pthread_mutex_t		cond_mutex;
	int			(*fired) (void *);

	unsigned long		flags;
} timer_thread_t;

typedef struct _timer_node {
	int		(*to_func) (void *);
	void		*to_arg;
	timeval_t	sands;
	rb_node_t	n;
} timer_node_t;


/* prototypes */
extern void timer_node_expire_now(timer_thread_t *, timer_node_t *);
extern void timer_node_init(timer_node_t *, int (*fn) (void *), void *);
extern void timer_node_add(timer_thread_t *, timer_node_t *, int);
extern int timer_node_pending(timer_node_t *);
extern int timer_node_del(timer_thread_t *, timer_node_t *);
extern int timer_thread_init(timer_thread_t *, const char *, int (*fired) (void *));
extern int timer_thread_signal(timer_thread_t *);
extern int timer_thread_destroy(timer_thread_t *);

#endif
