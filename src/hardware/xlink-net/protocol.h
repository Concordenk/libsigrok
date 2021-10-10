/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2021 Nickolay Kandaratskov <kandaratskov@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBSIGROK_HARDWARE_XLINK_NET_PROTOCOL_H
#define LIBSIGROK_HARDWARE_XLINK_NET_PROTOCOL_H

#include <stdint.h>
#include <glib.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "xlink-net"

#define TCP_BUFFER_SIZE	(128 * 1024)

struct addrinfo;

struct dev_channel
{
	unsigned					isbigendian : 1;
	unsigned					isunsigned  : 1;
	unsigned					isfloat     : 1;
	enum sr_mq				mq;
	enum sr_unit			unit;
	struct sr_channel*	channel;
	unsigned					frameoffset;
	unsigned					bits;
	float						scale;
	char*						name;
	struct dev_channel*	next;
};

struct dev_info
{
	unsigned					framelen;
	uint64_t					sr;
	char*						name;
	struct dev_channel*	analog;
	struct dev_channel*	digital;
	struct addrinfo*		addr;
	struct addrinfo*		addresses;
};

/** Private, per-device-instance driver context. */
struct dev_context
{
	struct dev_info*		di;
	char*						buffer;
	unsigned					buffer_maxsize;
	unsigned					buffer_size;
	uint64_t					limit_samples;
	uint64_t					recv_samples;
	GPollFD					pollfd;
	int						socket;
};

SR_PRIV int xlink_net_receive_data(int fd, int revents, void *cb_data);
SR_PRIV struct dev_info* xlink_net_load_info(const char* addr, const char* port);
SR_PRIV void xlink_net_free_info(struct dev_info *info);
SR_PRIV int xlink_net_stop(struct dev_context *devc);
SR_PRIV int xlink_net_start(struct dev_context *devc);

#endif
