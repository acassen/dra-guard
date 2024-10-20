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

#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>

/* Boolean flag - send messages to console as well as syslog */
static bool log_console = false;

void
enable_console_log(void)
{
	log_console = true;
}

void
log_message(const int facility, const char *format, ...)
{
	va_list args;
	char buf[256];

	va_start(args, format);
	vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	if (log_console) {
		fprintf(stderr, "%s\n", buf);
	}

	syslog(facility, "%s", buf);
}

void
conf_write(FILE *fp, const char *format, ...)
{
        va_list args;

        va_start(args, format);
        if (fp) {
                vfprintf(fp, format, args);
                fprintf(fp, "\n");
        } else
                log_message(LOG_INFO, format, args);

        va_end(args);
}
