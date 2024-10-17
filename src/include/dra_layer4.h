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

#ifndef _DRA_LAYER4_H
#define _DRA_LAYER4_H

/* Connection States */
enum connect_result {
	connect_error,
	connect_in_progress,
	connect_timeout,
	connect_fail,
	connect_success,
	connect_result_next
};

/* Prototypes */
extern enum connect_result socket_state(thread_ref_t, thread_func_t);
extern bool socket_connection_state(int, enum connect_result, thread_ref_t, thread_func_t, unsigned long);

#endif
