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

/* local includes */
#include "dra_guard.h"


/* Extern data */
extern data_t *daemon_data;


/*
 *	Disk I/O helpers
 */
static int
dra_disk_mkpath(char *path)
{
        struct stat sb;
        int last;
        char *p;
        p = path;

        if (p[0] == '/') ++p;
        for (last = 0; !last ; ++p) {
                if (p[0] == '\0')
                        last = 1;
                else
                        if (p[0] != '/')
                                continue;

                *p = '\0';
                if (!last && p[1] == '\0')
                        last = 1;

                if (mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
                        if (errno == EEXIST || errno == EISDIR) {
                                if (stat (path, &sb) < 0)
                                        return -1;
                                else
                                        if (!S_ISDIR(sb.st_mode))
                                                return -1;
                        } else
                                return -1;
                }
                if (!last) *p = '/';
        }
        return 0;
}

static int
dra_disk_mkdir(char *path)
{
        char *p;

        p = path + strlen(path) - 1;
        while (p-- != path) {
                if (*p == '/')
                        break;
        }

        if (p != path) *p = '\0';
        if (dra_disk_mkpath(path) < 0) {
                printf("%s(): Cant mkpath for file %s !!! (%m)\n"
                               , __FUNCTION__, path);
                return -1;
        }
        if (p != path) *p = '/';

        return 0;
}


/*
 *	Write stuff
 */
int
dra_disk_open_write(char *path)
{
        int ret, fd = -1;

        fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
        if (fd < 0) {
                /* Try to create path */
                ret = dra_disk_mkdir(path);
                if (ret < 0)
                        return -1;

                /* Ok target dir is created */
                fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
                if (fd < 0)
                        return -1;
        }

        return fd;
}

int
dra_disk_write(int fd, char *buffer, int size)
{
        int offset = 0, ret = 0;

        if (!fd)
                return -1;

  retry:
        ret = write(fd, buffer + offset, size - offset);
        if (ret < 0) {
                printf("%s(): error writing to file (%m)", __FUNCTION__);
                return -1;
        }

        offset += ret;

        if (offset < size)
                goto retry;

        return 0;
}


/*
 *      Read stuff
 */
int
dra_disk_open_read(char *path)
{
	int fd = -1;

	fd = open(path, O_RDONLY, 0644);
	if (fd < 0)
		return -1;

	return fd;
}

int
dra_disk_read(int fd, char *buffer, int size)
{
	int offset = 0, ret = 0;

	if (!fd)
		return -1;

  retry:
	ret = read(fd, buffer + offset, size - offset);
	if (ret < 0)
		return -1;

	if (ret == 0)
		return offset;

	offset += ret;

	if (offset < size)
		goto retry;

	return offset;
}
