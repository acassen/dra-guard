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

#ifndef _DRA_GUARD_H
#define _DRA_GUARD_H

#include <net/ethernet.h>
#include <net/if.h>
#include <linux/sctp.h>

#include "daemon.h"
#include "memory.h"
#include "bitops.h"
#include "utils.h"
#include "pidfile.h"
#include "signals.h"
#include "timer.h"
#include "timer_thread.h"
#include "scheduler.h"
#include "mpool.h"
#include "vector.h"
#include "command.h"
#include "rbtree.h"
#include "vty.h"
#include "logger.h"
#include "list_head.h"
#include "json_reader.h"
#include "json_writer.h"
#include "pkt_buffer.h"
#include "jhash.h"
#include "dra_if.h"
#include "dra_disk.h"
#include "dra_layer4.h"
#include "dra_htab.h"
#include "dra_json.h"
#include "dra_json_vty.h"
#include "dra_data.h"
#include "dra_vty.h"
#include "dra_bpf.h"
#include "dra_bpf_nat.h"
#include "dra_bpf_vty.h"
#include "dra_arp.h"
#include "dra_arp_vty.h"
#include "dra_mip.h"
#include "dra_mip_vty.h"
#include "dra_debug.h"
#include "dra_debug_vty.h"
#include "dra_diameter.h"
#include "dra_route_optim.h"
#include "dra_plugin.h"
#include "dra_plugin_vty.h"
#include "dra_sctp.h"
#include "dra_sctp_proto.h"
#include "dra_sctp_vty.h"

#endif
