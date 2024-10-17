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
#include <errno.h>

/* local includes */
#include "dra_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

static int plugin_config_write(vty_t *vty);
cmd_node_t plugin_node = {
        .node = PLUGIN_NODE,
        .parent_node = CONFIG_NODE,
        .prompt = "%s(plugin)# ",
        .config_write = plugin_config_write,
};


/*
 *	Command
 */
DEFUN(plugin,
      plugin_cmd,
      "plugin STRING path STRING ...",
      "Configure Plugin\n"
      "Plugin Name\n"
      "Path\n"
      "Path to plugin\n"
      "Arguments")
{
	dra_plugin_t *plugin;
	int err;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	plugin = dra_plugin_get(argv[0]);
	if (plugin) {
		vty_out(vty, "%% Plugin '%s' already configured%s", argv[0], VTY_NEWLINE);
		dra_plugin_put(plugin);
		return CMD_WARNING;
	}
	plugin = dra_plugin_alloc(argv[0]);
	strlcpy(plugin->path, argv[1], DRA_PATH_MAX_LEN);
	dra_plugin_argscpy(plugin, argv, argc);

	err = dra_plugin_load(plugin, argv, argc);
	if (err) {
		vty_out(vty, "%% unable to load plugin '%s'%s", plugin->name, VTY_NEWLINE);
		dra_plugin_put(plugin);
		return CMD_WARNING;
	}

	vty_out(vty, "Success loading plugin '%s'%s", plugin->name, VTY_NEWLINE);
	dra_plugin_put(plugin);
	return CMD_SUCCESS;
}

DEFUN(no_plugin,
      no_plugin_cmd,
      "no plugin WORD",
      "unconfigure Plugin\n"
      "Plugin Name\n")
{
	dra_plugin_t *plugin;
	int err;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	plugin = dra_plugin_get(argv[0]);
	if (!plugin) {
		vty_out(vty, "%% unknown plugin '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	dra_plugin_put(plugin);

	err = dra_plugin_release(plugin);
	if (err) {
		vty_out(vty, "%% cant unload plugin '%s' (refcnt:%d)%s"
			   , argv[0], plugin->refcnt, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "Success unloading plugin '%s'%s", argv[0], VTY_NEWLINE);
	return CMD_SUCCESS;
}

/* Configuration writer */
static int
plugin_config_write(vty_t *vty)
{
	list_head_t *l = &daemon_data->plugins;
	dra_plugin_t *plugin;

	if (list_empty(l))
		return CMD_SUCCESS;

	list_for_each_entry(plugin, l, next) {
		vty_out(vty, "plugin %s path %s %s%s"
			   , plugin->name, plugin->path, plugin->args
			   , VTY_NEWLINE);
	}
	vty_out(vty, "!%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
dra_plugin_vty_init(void)
{
	/* Install MIP commands. */
	install_node(&plugin_node);
	install_element(CONFIG_NODE, &plugin_cmd);
	install_element(CONFIG_NODE, &no_plugin_cmd);

	install_default(PLUGIN_NODE);

	return 0;
}
