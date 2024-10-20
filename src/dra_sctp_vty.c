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
#include <sys/stat.h>
#include <net/if.h>
#include <errno.h>

/* local includes */
#include "dra_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

static int sctp_proxy_config_write(vty_t *vty);
cmd_node_t sctp_proxy_node = {
	.node = SCTP_PROXY_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(sctp-proxy)# ",
	.config_write = sctp_proxy_config_write,
};


/*
 *	SCTP proxy command
 */
DEFUN(sctp_proxy,
      sctp_proxy_cmd,
      "sctp-proxy WORD",
      "Configure SCTP Listener\n"
      "Context Name\n")
{
	dra_sctp_proxy_t *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Already existing ? */
	new = dra_sctp_proxy_get(argv[0]);
	if (!new)
		new = dra_sctp_proxy_alloc(argv[0]);


	vty->node = SCTP_PROXY_NODE;
	vty->index = new;
	return CMD_SUCCESS;
}

DEFUN(sctp_proxy_listen,
      sctp_proxy_listen_cmd,
      "listen STRING",
      "Configure SCTP Listener bind addresses\n"
      "String of address in form of A.B.C.D,A.B.C.D,..:port\n")
{
	dra_sctp_proxy_t *p = vty->index;
	char *tmp_str;
	int cnt;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	tmp_str = MALLOC(DRA_STR_MAX_LEN);
	strlcpy(tmp_str, argv[0], DRA_STR_MAX_LEN);
	cnt = dra_sctp_parse_addrs_list_port(tmp_str, &p->addrs);
	if (cnt < 0) {
		vty_out(vty, "%% bad address list '%s'%s", argv[0], VTY_NEWLINE);
		FREE(tmp_str);
		return CMD_WARNING;
	}

	p->addrs_cnt = cnt;
	sctp_assoc_str(p->addrs, p->addrs_cnt, p->addrs_str, DRA_STR_MAX_LEN);
	FREE(tmp_str);
	return CMD_SUCCESS;
}

DEFUN(sctp_proxy_ostreams,
      sctp_proxy_ostreams_cmd,
      "num-ostreams INTEGER",
      "Configure SCTP number of outbound streams\n"
      "OutBound streams in range [1..65535]\n")
{
	dra_sctp_proxy_t *p = vty->index;
	struct sctp_initmsg *initmsg = &p->server_initmsg;
	int num = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("OutBound streams", num, argv[0], 1, 65535);
	initmsg->sinit_num_ostreams = num;
	return CMD_SUCCESS;
}

DEFUN(sctp_proxy_instreams,
      sctp_proxy_instreams_cmd,
      "max-instreams INTEGER",
      "Configure SCTP Maximum number of inbound streams\n"
      "Maximum InBound streams in range [1..65535]\n")
{
	dra_sctp_proxy_t *p = vty->index;
	struct sctp_initmsg *initmsg = &p->server_initmsg;
	int num = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Max InBound streams", num, argv[0], 1, 65535);
	initmsg->sinit_max_instreams = num;
	return CMD_SUCCESS;
}

DEFUN(sctp_proxy_connect,
      sctp_proxy_connect_cmd,
      "connect STRING",
      "Configure SCTP remote connection addresses\n"
      "String of address in form of A.B.C.D,A.B.C.D,..:port\n")
{
	dra_sctp_proxy_t *p = vty->index;
	char *tmp_str;
	int cnt;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	tmp_str = MALLOC(DRA_STR_MAX_LEN);
	strlcpy(tmp_str, argv[0], DRA_STR_MAX_LEN);
	cnt = dra_sctp_parse_addrs_list_port(tmp_str, &p->connect_addrs);
	if (cnt < 0) {
		vty_out(vty, "%% bad address list '%s'%s", argv[0], VTY_NEWLINE);
		FREE(tmp_str);
		return CMD_WARNING;
	}

	p->connect_addrs_cnt = cnt;
	sctp_assoc_str(p->connect_addrs, p->connect_addrs_cnt, p->connect_addrs_str, DRA_STR_MAX_LEN);
	FREE(tmp_str);
	return CMD_SUCCESS;
}

DEFUN(sctp_proxy_connect_max_attempts,
      sctp_proxy_connect_max_attempts_cmd,
      "connect-max-attempts INTEGER",
      "Configure SCTP Client Maximum number of connection attempts\n"
      "Maximum attempts in range [1..10]\n")
{
	dra_sctp_proxy_t *p = vty->index;
	struct sctp_initmsg *initmsg = &p->client_initmsg;
	int num = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Max Attempts", num, argv[0], 1, 65535);
	initmsg->sinit_max_attempts = num;
	return CMD_SUCCESS;
}

DEFUN(sctp_proxy_connect_max_init_timeo,
      sctp_proxy_connect_max_init_timeo_cmd,
      "connect-max-init-timeout INTEGER",
      "Configure SCTP Client Maximum init connection timeout\n"
      "Maximum timeout in range [1..10]\n")
{
	dra_sctp_proxy_t *p = vty->index;
	struct sctp_initmsg *initmsg = &p->client_initmsg;
	int num = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Max Attempts", num, argv[0], 1, 65535);
	initmsg->sinit_max_init_timeo = num;
	return CMD_SUCCESS;
}


DEFUN(sctp_proxy_workers,
      sctp_proxy_workers_cmd,
      "workers INTEGER",
      "Configure SCTP number of pallel workers\n"
      "Number of Workers in range [1..64]\n")
{
	dra_sctp_proxy_t *p = vty->index;
	int num = 0;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Number of Workers", num, argv[0], 1, 64);
	p->thread_cnt = num;
	return CMD_SUCCESS;
}

DEFUN(sctp_proxy_ingress_assoc_local_nat,
      sctp_proxy_ingress_assoc_local_nat_cmd,
      "ingress-assoc-local-ip nat A.B.C.D A.B.C.D A.B.C.D",
      "Configure SCTP Proxy local NAT mode for Ingress associations\n"
      "Netmask to match\n"
      "IPv4 Address\n"
      "IP prefix to nat\n"
      "IPv4 Address\n"
      "IP prefix nat\n"
      "IPv4 Address\n")
{
	dra_sctp_proxy_t *p = vty->index;

	if (argc < 3) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!p->addrs_cnt || !p->connect_addrs_cnt) {
		vty_out(vty, "%% you MUST configure 'bind' and 'connect' directives%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!inet_ston(argv[0], &p->local_nat_netmask)) {
		vty_out(vty, "%% malformed IP Address:%s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!inet_ston(argv[1], &p->local_nat_ip_match)) {
		vty_out(vty, "%% malformed IP Address:%s%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!inet_ston(argv[2], &p->local_nat_ip)) {
		vty_out(vty, "%% malformed IP Address:%s%s", argv[2], VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(SCTP_FL_LOCAL_NAT, &p->flags);
	dra_sctp_proto_init(p);
	dra_sctp_worker_start(p);
	return CMD_SUCCESS;
}

DEFUN(sctp_proxy_mip6_agent_info_host_match_rewrite,
      sctp_proxy_mip6_agent_info_match_rewrite_cmd,
      "mip6-agent-info match-debug-rewrite-ula",
      "configure SCTP Proxy Rewriting Update-Localtion-Answer\n"
      "rewrite ULA matching debug-profil entries\n")
{
	dra_sctp_proxy_t *p = vty->index;

	__set_bit(SCTP_FL_MATCH_TARGET_REWRITE_ULA, &p->flags);
	return CMD_SUCCESS;
}

DEFUN(no_sctp_proxy_mip6_agent_info_host_rewrite,
      no_sctp_proxy_mip6_agent_info_rewrite_cmd,
      "no mip6-agent-info",
      "unconfigure SCTP Proxy Rewriting Update-Localtion-Answer\n"
      "mip-home-agent-host\n")
{
	dra_sctp_proxy_t *p = vty->index;

	if (!__test_bit(SCTP_FL_MATCH_TARGET_REWRITE_ULA, &p->flags)) {
		vty_out(vty, "%% no mip6-agent-info configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	__clear_bit(SCTP_FL_MATCH_TARGET_REWRITE_ULA, &p->flags);
	return CMD_SUCCESS;
}

DEFUN(sctp_proxy_plugin,
      sctp_proxy_plugin_cmd,
      "plugin STRING",
      "Add SCTP Proxy plugin\n"
      "Plugin Name\n")
{
	dra_sctp_proxy_t *p = vty->index;
	dra_plugin_t *plugin;
	int err;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	plugin = dra_plugin_get(argv[0]);
	if (!plugin) {
		vty_out(vty, "%% unknown Plugin '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = dra_sctp_proxy_plugin_add(p, plugin);
	if (err) {
		vty_out(vty, "%% Cant use Plugin '%s' (max plugin number:%d reached)%s"
			   , argv[0], DRA_SCTP_MAX_PLUGIN, VTY_NEWLINE);
		dra_plugin_put(plugin);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(no_sctp_proxy_plugin,
      no_sctp_proxy_plugin_cmd,
      "no plugin STRING",
      "Del SCTP Proxy plugin\n"
      "Plugin Name\n")
{
	dra_sctp_proxy_t *p = vty->index;
	int err;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = dra_sctp_proxy_plugin_del(p, argv[0]);
	if (err) {
		vty_out(vty, "%% Unknown plugin '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}


/*
 *	Configuration writer
 */
static int
sctp_proxy_config_write(vty_t *vty)
{
	list_head_t *l = &daemon_data->sctp_proxys;
	struct sockaddr_in *addr;
	struct sctp_initmsg *initmsg;
	dra_sctp_proxy_t *p;
	int i;

	if (list_empty(l))
		return CMD_SUCCESS;

	list_for_each_entry(p, l, next) {
		vty_out(vty, "sctp-proxy %s%s", p->name, VTY_NEWLINE);
		if (p->addrs_cnt) {
			addr = (struct sockaddr_in *) &p->addrs[0];
			vty_out(vty, " bind %s:%d%s", p->addrs_str, ntohs(addr->sin_port), VTY_NEWLINE);
		}

		initmsg = &p->server_initmsg;
		if (initmsg->sinit_num_ostreams)
			vty_out(vty, " num-ostreams %d%s", initmsg->sinit_num_ostreams, VTY_NEWLINE);
		if (initmsg->sinit_max_instreams)
			vty_out(vty, " max-instreams %d%s", initmsg->sinit_max_instreams, VTY_NEWLINE);
		vty_out(vty, " workers %d%s", p->thread_cnt, VTY_NEWLINE);
		if (p->connect_addrs_cnt) {
			addr = (struct sockaddr_in *) &p->connect_addrs[0];
			vty_out(vty, " connect %s:%d%s", p->connect_addrs_str, ntohs(addr->sin_port), VTY_NEWLINE);
		}

		if (__test_bit(SCTP_FL_LOCAL_NAT, &p->flags))
			vty_out(vty, " ingress-assoc-local-ip nat %u.%u.%u.%u %u.%u.%u.%u  %u.%u.%u.%u %s"
				   , NIPQUAD(p->local_nat_netmask)
				   , NIPQUAD(p->local_nat_ip_match)
				   , NIPQUAD(p->local_nat_ip)
				   , VTY_NEWLINE);

		initmsg = &p->client_initmsg;
		if (initmsg->sinit_max_attempts)
			vty_out(vty, " connect-max-attempts %d%s", initmsg->sinit_max_attempts, VTY_NEWLINE);
		if (initmsg->sinit_max_init_timeo)
			vty_out(vty, " connect-max-init-timeout %d%s", initmsg->sinit_max_init_timeo, VTY_NEWLINE);
		if (__test_bit(SCTP_FL_MATCH_TARGET_REWRITE_ULA, &p->flags))
			vty_out(vty, " mip6-agent-info match-debug-rewrite-ula%s", VTY_NEWLINE);
		for (i = 0; i < p->plugin_cnt; i++)
			vty_out(vty, " plugin %s%s", p->plugin[i].plugin->name, VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
dra_sctp_vty_init(void)
{

	/* Install SCTP commands. */
	install_node(&sctp_proxy_node);
	install_element(CONFIG_NODE, &sctp_proxy_cmd);

	/* Listener cmd */
	install_default(SCTP_PROXY_NODE);
	install_element(SCTP_PROXY_NODE, &sctp_proxy_listen_cmd);
	install_element(SCTP_PROXY_NODE, &sctp_proxy_ostreams_cmd);
	install_element(SCTP_PROXY_NODE, &sctp_proxy_instreams_cmd);
	install_element(SCTP_PROXY_NODE, &sctp_proxy_workers_cmd);
	install_element(SCTP_PROXY_NODE, &sctp_proxy_connect_cmd);
	install_element(SCTP_PROXY_NODE, &sctp_proxy_connect_max_attempts_cmd);
	install_element(SCTP_PROXY_NODE, &sctp_proxy_connect_max_init_timeo_cmd);
	install_element(SCTP_PROXY_NODE, &sctp_proxy_ingress_assoc_local_nat_cmd);
	install_element(SCTP_PROXY_NODE, &sctp_proxy_mip6_agent_info_match_rewrite_cmd);
	install_element(SCTP_PROXY_NODE, &no_sctp_proxy_mip6_agent_info_rewrite_cmd);
	install_element(SCTP_PROXY_NODE, &sctp_proxy_plugin_cmd);
	install_element(SCTP_PROXY_NODE, &no_sctp_proxy_plugin_cmd);

	return 0;
}
