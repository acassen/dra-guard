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
#include <net/if.h>
#include <linux/if_link.h>
#include <errno.h>
#include <libbpf.h>

/* local includes */
#include "dra_guard.h"

/* Local data */
static const char *pin_basedir = "/sys/fs/bpf";


/* Extern data */
extern data_t *daemon_data;

/*
 *	BPF MAP related
 */
int
dra_bpf_map_load(dra_bpf_opts_t *opts)
{
	struct bpf_map *map;

	/* MAP ref for faster access */
	opts->bpf_maps = MALLOC(sizeof(dra_bpf_maps_t) * DRA_BPF_MAP_CNT);

	map = dra_bpf_load_map(opts->bpf_obj, "arp_ip_nat_rules");
	if (!map)
		return -1;
	opts->bpf_maps[DRA_BPF_MAP_ARP_IP_NAT].map = map;

	map = dra_bpf_load_map(opts->bpf_obj, "ip_nat_rules");
	if (!map)
		return -1;
	opts->bpf_maps[DRA_BPF_MAP_IP_NAT].map = map;

	map = dra_bpf_load_map(opts->bpf_obj, "sctp_ip_nat_rules");
	if (!map)
		return -1;
	opts->bpf_maps[DRA_BPF_MAP_SCTP_IP_NAT].map = map;

	return 0;
}

int
dra_bpf_map_unload(dra_bpf_opts_t *opts)
{
	if (opts->bpf_maps)
		FREE(opts->bpf_maps);
	return 0;
}

/*
 *	BPF opts related
 */
dra_bpf_opts_t *
dra_bpf_opts_alloc(int type, void (*bpf_unload) (dra_bpf_opts_t *))
{
	dra_bpf_opts_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	new->type = type;
	new->bpf_unload = bpf_unload;

	return new;
}

int
dra_bpf_opts_add(dra_bpf_opts_t *opts, list_head_t *l)
{
	list_add_tail(&opts->next, l);
	return 0;
}

int
dra_bpf_opts_del(dra_bpf_opts_t *opts)
{
	if (opts->bpf_unload)
		(*opts->bpf_unload) (opts);
	list_head_del(&opts->next);
	dra_bpf_map_unload(opts);
	FREE(opts);
	return 0;
}

dra_bpf_opts_t *
dra_bpf_opts_exist(list_head_t *l, int argc, const char **argv)
{
	dra_bpf_opts_t *opts;
	int ifindex;

	if (argc < 2)
		return 0;

	ifindex = if_nametoindex(argv[2]);
	if (!ifindex)
		return NULL;

	list_for_each_entry(opts, l, next) {
		if (opts->ifindex == ifindex &&
		    !strncmp(opts->filename, argv[1], DRA_STR_MAX_LEN))
			return opts;
	}

	return NULL;
}

dra_bpf_opts_t *
dra_bpf_opts_get_by_label(list_head_t *l, const char *label)
{
	dra_bpf_opts_t *opts;

	list_for_each_entry(opts, l, next) {
		if (!strncmp(opts->label, label, DRA_STR_MAX_LEN)) {
			return opts;
		}
	}

	return NULL;
}

void
dra_bpf_opts_destroy(list_head_t *l)
{
	dra_bpf_opts_t *opts, *_opts;

	list_for_each_entry_safe(opts, _opts, l, next)
		dra_bpf_opts_del(opts);
	INIT_LIST_HEAD(l);
}

int
dra_bpf_opts_load(dra_bpf_opts_t *opts, vty_t *vty, int argc, const char **argv,
		  int (*bpf_load) (dra_bpf_opts_t *))
{
	int err, ifindex;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return -1;
	}

	strlcpy(opts->label, argv[0], DRA_STR_MAX_LEN-1);
	strlcpy(opts->filename, argv[1], DRA_STR_MAX_LEN-1);
	ifindex = if_nametoindex(argv[2]);
	if (argc == 4)
		strlcpy(opts->progname, argv[3], DRA_STR_MAX_LEN-1);
	if (!ifindex) {
		vty_out(vty, "%% Error resolving interface %s (%m)%s"
			   , argv[2]
			   , VTY_NEWLINE);
		return -1;
	}
	opts->ifindex = ifindex;
	opts->vty = vty;

	err = (*bpf_load) (opts);
	if (err) {
		vty_out(vty, "%% Error loading eBPF program:%s on ifindex:%d%s"
			   , opts->filename
			   , opts->ifindex
			   , VTY_NEWLINE);
		/* Reset data */
		memset(opts, 0, sizeof(dra_bpf_opts_t));
		return -1;
	}

	/* Loading MAPs */
	err = dra_bpf_map_load(opts);
	if (err) {
		vty_out(vty, "%% Error loading eBPF MAPs from program:%s on ifindex:%d%s"
			   , opts->filename
			   , opts->ifindex
			   , VTY_NEWLINE);

		/* Unload */
		if (opts->bpf_unload)
			(*opts->bpf_unload) (opts);

		/* Reset data */
		memset(opts, 0, sizeof(dra_bpf_opts_t));
		return -1;
	}

	log_message(LOG_INFO, "Success loading eBPF program:%s on ifindex:%d"
			    , opts->filename
			    , opts->ifindex);
	return 0;
}


/*
 *	BPF related
 */
static int
dra_bpf_log_message(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !(debug & 16))
		return 0;

	log_message(LOG_INFO, format, args);
	return 0;
}

struct bpf_map *
dra_bpf_load_map(struct bpf_object *obj, const char *map_name)
{
	struct bpf_map *map = NULL;
	char errmsg[DRA_XDP_STRERR_BUFSIZE];

	map = bpf_object__find_map_by_name(obj, map_name);
	if (!map) {
		libbpf_strerror(errno, errmsg, DRA_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): BPF: error mapping tab:%s err:%d (%s)"
				    , __FUNCTION__
				    , map_name
				    , errno, errmsg);
		return NULL;
	}

	return map;
}

static void
dra_bpf_cleanup_maps(struct bpf_object *obj, dra_bpf_opts_t *opts)
{
	char errmsg[DRA_XDP_STRERR_BUFSIZE];
	struct bpf_map *map;
	vty_t *vty = opts->vty;

	bpf_object__for_each_map(map, obj) {
		char buf[DRA_STR_MAX_LEN];
		int len, err;

		len = snprintf(buf, DRA_STR_MAX_LEN, "%s/%d/%s"
						   , pin_basedir
						   , opts->ifindex
						   , bpf_map__name(map));
		if (len < 0) {
			vty_out(vty, "%% BPF: error preparing path for map(%s)%s"
				   , bpf_map__name(map), VTY_NEWLINE);
			return;
		}

		if (len > DRA_STR_MAX_LEN) {
			vty_out(vty, "%% BPF error, pathname too long to store map(%s)%s"
				   , bpf_map__name(map), VTY_NEWLINE);
			return;
		}

		if (access(buf, F_OK) != -1) {
			vty_out(vty, "BPF: unpinning previous map in %s%s"
				   , buf, VTY_NEWLINE);
			err = bpf_map__unpin(map, buf);
			if (err) {
				libbpf_strerror(err, errmsg, DRA_XDP_STRERR_BUFSIZE);
				vty_out(vty, "%% BPF error:%d (%s)%s"
					   , err, errmsg, VTY_NEWLINE);
				continue;
			}
		}
	}
}

static struct bpf_object *
dra_bpf_load_file(dra_bpf_opts_t *opts)
{
	struct bpf_object *bpf_obj;
	char errmsg[DRA_XDP_STRERR_BUFSIZE];
	vty_t *vty = opts->vty;
	int err;

	/* open eBPF file */
	bpf_obj = bpf_object__open(opts->filename);
	if (!bpf_obj) {
		libbpf_strerror(errno, errmsg, DRA_XDP_STRERR_BUFSIZE);
		vty_out(vty, "%% BPF: error opening bpf file err:%d (%s)%s"
			   , errno, errmsg, VTY_NEWLINE);
		return NULL;
	}

	/* Release previously stalled maps. Our lazzy strategy here is to
	 * simply erase previous maps during startup. Maybe if we want to
	 * implement some kind of graceful-restart we need to reuse-maps
	 * and rebuild local daemon tracking. Auto-pinning is done during
	 * bpf_object__load.
	 * FIXME: Implement graceful-restart */
	dra_bpf_cleanup_maps(bpf_obj, opts);

	/* Finally load it */
	err = bpf_object__load(bpf_obj);
	if (err) {
		libbpf_strerror(err, errmsg, DRA_XDP_STRERR_BUFSIZE);
		vty_out(vty, "%% BPF: error loading bpf_object err:%d (%s)%s"
			   , err, errmsg, VTY_NEWLINE);
		bpf_object__close(bpf_obj);
		return NULL;
	}

	return bpf_obj;
}

static struct bpf_program *
dra_bpf_load_prog(dra_bpf_opts_t *opts)
{
	struct bpf_program *bpf_prog = NULL;
	struct bpf_object *bpf_obj;
	int len;

	/* Preprare pin_dir. We decided ifindex to be part of
	 * path to be able to load same bpf program on different
	 * ifindex */
	len = snprintf(opts->pin_root_path, DRA_STR_MAX_LEN, "%s/%d"
					  , pin_basedir, opts->ifindex);
	if (len < 0) {
		log_message(LOG_INFO, "%s(): Error preparing eBPF pin_dir for ifindex:%d"
				    , __FUNCTION__
				    , opts->ifindex);
		return NULL;
	}

	if (len > DRA_STR_MAX_LEN) {
		log_message(LOG_INFO, "%s(): Error preparing BPF pin_dir for ifindex:%d (path_too_long)"
				    , __FUNCTION__
				    , opts->ifindex);
		return NULL;
	}

	/* Load object */
	bpf_obj = dra_bpf_load_file(opts);
	if (!bpf_obj)
		return NULL;

	/* Attach prog to interface */
	if (opts->progname[0]) {
		bpf_prog = bpf_object__find_program_by_name(bpf_obj, opts->progname);
		if (!bpf_prog) {
			log_message(LOG_INFO, "%s(): BPF: unknown program:%s (fallback to first one)"
					    , __FUNCTION__
					    , opts->progname);
		}
	}

	if (!bpf_prog) {
		bpf_prog = bpf_object__next_program(bpf_obj, NULL);
		if (!bpf_prog) {
			log_message(LOG_INFO, "%s(): BPF: no program found in file:%s"
					    , __FUNCTION__
					    , opts->filename);
			goto err;
		}
	}

	opts->bpf_obj = bpf_obj;
	return bpf_prog;

  err:
	bpf_object__close(bpf_obj);
	return NULL;
}


int
dra_xdp_load(dra_bpf_opts_t *opts)
{
	struct bpf_program *bpf_prog = NULL;
	struct bpf_link *bpf_lnk;
	char errmsg[DRA_XDP_STRERR_BUFSIZE];
	int err;

	/* Load eBPF prog */
	bpf_prog = dra_bpf_load_prog(opts);
	if (!bpf_prog)
		return -1;

	/* Detach previously stalled XDP programm */
	err = bpf_xdp_detach(opts->ifindex, XDP_FLAGS_DRV_MODE, NULL);
	if (err) {
		libbpf_strerror(err, errmsg, DRA_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant detach previous XDP programm (%s)"
				    , __FUNCTION__
				    , errmsg);
	}

	/* Attach XDP */
	bpf_lnk = bpf_program__attach_xdp(bpf_prog, opts->ifindex);
	if (!bpf_lnk) {
		libbpf_strerror(errno, errmsg, DRA_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): XDP: error attaching program:%s to ifindex:%d err:%d (%s)"
				    , __FUNCTION__
				    , bpf_program__name(bpf_prog)
				    , opts->ifindex
				    , errno, errmsg);
		goto err;
	}

	opts->bpf_lnk = bpf_lnk;
	return 0;

  err:
	return -1;
}

void
dra_xdp_unload(dra_bpf_opts_t *opts)
{
	bpf_link__destroy(opts->bpf_lnk);
	bpf_object__close(opts->bpf_obj);
}


/*
 *	Qdisc related
 */
static int
dra_qdisc_clsact_add(struct bpf_tc_hook *q_hook)
{
	char errmsg[DRA_XDP_STRERR_BUFSIZE];
	int err;

	bpf_tc_hook_destroy(q_hook);	/* Release previously stalled entry */
	err = bpf_tc_hook_create(q_hook);
	if (err) {
		libbpf_strerror(err, errmsg, DRA_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant create TC_HOOK to ifindex:%d (%s)"
				    , __FUNCTION__
				    , q_hook->ifindex
				    , errmsg);
		return 1;
	}

	return 0;
}

static int
dra_tc_filter_add(struct bpf_tc_hook *q_hook, enum bpf_tc_attach_point direction,
		  const struct bpf_program *bpf_prog)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 0,
			    .flags = BPF_TC_F_REPLACE);
	char errmsg[DRA_XDP_STRERR_BUFSIZE];
	int err;

	q_hook->attach_point = direction;
	tc_opts.prog_fd = bpf_program__fd(bpf_prog);
	err = bpf_tc_attach(q_hook, &tc_opts);
	if (err) {
		libbpf_strerror(err, errmsg, DRA_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant attach eBPF prog_fd:%d to ifindex:%d %s (%s)"
				    , __FUNCTION__
				    , tc_opts.prog_fd
				    , q_hook->ifindex
				    , (direction == BPF_TC_INGRESS) ? "ingress" : "egress"
				    , errmsg);
		return 1;
	}

	return 0;
}

int
dra_qdisc_clsact_load(dra_bpf_opts_t *opts)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, q_hook, .ifindex = opts->ifindex,
			    .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
	struct bpf_program *bpf_prog = NULL;
	int err = 0;

	/* Load eBPF prog */
	bpf_prog = dra_bpf_load_prog(opts);
	if (!bpf_prog)
		return -1;

	/* Create Qdisc Clsact & attach {in,e}gress filters */
	err = err ? : dra_qdisc_clsact_add(&q_hook);
	err = err ? : dra_tc_filter_add(&q_hook, BPF_TC_EGRESS, bpf_prog);
	if (err) {
		bpf_object__close(opts->bpf_obj);
		return -1;
	}

	return 0;
}

void
dra_qdisc_clast_unload(dra_bpf_opts_t *opts)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, q_hook, .ifindex = opts->ifindex,
			    .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
	bpf_tc_hook_destroy(&q_hook);
	bpf_object__close(opts->bpf_obj);
}


/*
 *	BPF service init
 */
int
dra_bpf_init(void)
{
	libbpf_set_print(dra_bpf_log_message);
	return 0;
}

int
dra_bpf_destroy(void)
{
	dra_bpf_opts_destroy(&daemon_data->bpf_progs);
	return 0;
}
