# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Soft:        The main goal of dra-guard is to provide robust and secure
#              extensions to DRA feature (Diameter Routing Agent). DRA are
#              used in mobile networks in order to redirect users terminals
#              to their HPLMN in Roaming situations. DRA-Guard implements a
#              set of features to manipulate and analyze Diameter payloads.
#
# Authors:     Alexandre Cassen, <acassen@gmail.com>
#
#              This program is part of FreeMobile product line.
#
# Copyright (C) 2024 Alexandre Cassen, <acassen@gmail.com>
#

CC	 ?= gcc
INCLUDES = -Iinclude -I../lib -I../libbpf/src -I../libbpf/src/uapi
CFLAGS	 = -g -O2 -ggdb $(INCLUDES) -Werror -Wall -Wunused -Wstrict-prototypes -D_GNU_SOURCE
#DEFS	 = -D_DEBUG_
DEFS	 =
COMPILE	 = $(CC) $(CFLAGS) $(DEFS)

OBJS = 	main.o dra_data.o dra_disk.o dra_if.o dra_vty.o dra_htab.o		\
	dra_debug.o dra_debug_vty.o dra_bpf.o dra_bpf_nat.o dra_bpf_vty.o	\
	dra_mip.o dra_mip_vty.o dra_arp.o dra_arp_vty.o dra_layer4.o		\
	dra_sctp.o dra_sctp_proto.o dra_sctp_vty.o dra_diameter.o dra_json.o	\
	dra_json_vty.o dra_plugin.o dra_plugin_vty.o dra_pcap.o dra_route_optim.o

HEADERS = $(OBJS:.o=.h)

.c.o:
	@echo "  CC" $@
	@$(COMPILE) -c $<

all:	$(OBJS)

clean:
	rm -f *.a *.o *~
