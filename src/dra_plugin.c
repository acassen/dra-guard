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
#include <dlfcn.h>

/* local includes */
#include "dra_guard.h"

/* Local data */
pthread_mutex_t dra_plugin_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Extern data */
extern data_t *daemon_data;


/*
 *	plugin Utilities
 */
dra_plugin_t *
dra_plugin_get(const char *name)
{
	list_head_t *l = &daemon_data->plugins;
	dra_plugin_t *plugin;

	pthread_mutex_lock(&dra_plugin_mutex);
	list_for_each_entry(plugin, l, next) {
		if (!strncmp(name, plugin->name, DRA_NAME_MAX_LEN)) {
			pthread_mutex_unlock(&dra_plugin_mutex);
			__sync_add_and_fetch(&plugin->refcnt, 1);
			return plugin;
		}
	}
	pthread_mutex_unlock(&dra_plugin_mutex);

	return NULL;
}

int
dra_plugin_put(dra_plugin_t *plugin)
{
	if (!plugin)
		return -1;

	__sync_sub_and_fetch(&plugin->refcnt, 1);
	return 0;
}

static int
dra_plugin_add(dra_plugin_t *plugin)
{
	pthread_mutex_lock(&dra_plugin_mutex);
	list_add_tail(&plugin->next, &daemon_data->plugins);
	pthread_mutex_unlock(&dra_plugin_mutex);
	return 0;
}

static int
__dra_plugin_del(dra_plugin_t *plugin)
{
	list_head_del(&plugin->next);
	return 0;
}

int
dra_plugin_load(dra_plugin_t *plugin, const char *argv[], int argc)
{
	plugin->hdl = dlopen(plugin->path, RTLD_LAZY);
	if (plugin->hdl == NULL) {
		log_message(LOG_INFO, "%s(): error loading '%s' (%s)"
				    , __FUNCTION__, plugin->path, dlerror());
		return -1;
	}

	plugin->init = dlsym(plugin->hdl, "init");
	if (!dlerror()) {
		log_message(LOG_INFO, "%s(): plugin '%s' is supporting 'init()' callback"
				    , __FUNCTION__, plugin->name);
		(*plugin->init) (argv, argc);
	}

	plugin->destroy = dlsym(plugin->hdl, "destroy");
	if (!dlerror()) {
		log_message(LOG_INFO, "%s(): plugin '%s' is supporting 'destroy()' callback"
				    , __FUNCTION__, plugin->name);
	}

	plugin->generic_pkt = dlsym(plugin->hdl, "generic_pkt");
	if (!dlerror()) {
		log_message(LOG_INFO, "%s(): plugin '%s' is supporting 'generic_pkt()' callback"
				    , __FUNCTION__, plugin->name);
	}

	plugin->ingress_pkt_read = dlsym(plugin->hdl, "ingress_pkt_read");
	if (!dlerror()) {
		log_message(LOG_INFO, "%s(): plugin '%s' is supporting 'ingress_pkt_read()' callback"
				    , __FUNCTION__, plugin->name);
	}

	plugin->egress_pkt_read = dlsym(plugin->hdl, "egress_pkt_read");
	if (!dlerror()) {
		log_message(LOG_INFO, "%s(): plugin '%s' is supporting 'egress_pkt_read()' callback"
				    , __FUNCTION__, plugin->name);
	}

	return 0;
}

static int
dra_plugin_unload(dra_plugin_t *plugin)
{
	int err;

	if (!plugin->hdl)
		return -1;

	if (plugin->destroy)
		(*plugin->destroy) ();

	err = dlclose(plugin->hdl);
	if (err) {
		log_message(LOG_INFO, "%s(): error unloading '%s' (%s)"
				    , __FUNCTION__, plugin->name, dlerror());
		return -1;
	}

	return 0;
}


/*
 *	Plugin Service init
 */
int
dra_plugin_argscpy(dra_plugin_t *plugin, const char *argv[], int argc)
{
	int i;

	for (i = 2; i < argc; i++) {
		if (i > 2)
			strlcat(plugin->args, " ", DRA_PLUGIN_ARGS_MAX_LEN);
		strlcat(plugin->args, argv[i], DRA_PLUGIN_ARGS_MAX_LEN);
	}

	return 0;
}

dra_plugin_t *
dra_plugin_alloc(const char *name)
{
	dra_plugin_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	strlcpy(new->name, name, DRA_NAME_MAX_LEN);

	dra_plugin_add(new);
	__sync_add_and_fetch(&new->refcnt, 1);
	return new;
}

static int
__dra_plugin_release(dra_plugin_t *plugin)
{
	__dra_plugin_del(plugin);
	dra_plugin_unload(plugin);
	FREE(plugin);
	return 0;
}

int
dra_plugin_release(dra_plugin_t *plugin)
{
	if (__sync_add_and_fetch(&plugin->refcnt, 0) != 0)
		return -1;

	pthread_mutex_lock(&dra_plugin_mutex);
	__dra_plugin_release(plugin);
	pthread_mutex_unlock(&dra_plugin_mutex);
	return 0;
}

int
dra_plugin_destroy(void)
{
	dra_plugin_t *plugin, *_plugin;

	pthread_mutex_lock(&dra_plugin_mutex);
	list_for_each_entry_safe(plugin, _plugin, &daemon_data->plugins, next)
		__dra_plugin_release(plugin);
	pthread_mutex_unlock(&dra_plugin_mutex);

	return 0;
}
