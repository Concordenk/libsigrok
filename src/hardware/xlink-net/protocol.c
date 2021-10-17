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

#include <config.h>
#include <math.h>
#ifdef _WIN32
#define _WIN32_WINNT 0x0501
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <glib.h>
#include <string.h>
#include <unistd.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#include <errno.h>

#include "protocol.h"

#define	MAX_DESCRIPTION_SIZE	1024
#define	CONVERSION_BUFF_SIZE	1024
#define  WAIT_TIME				2000000 /* 2 seconds */

static struct dev_info* xlink_net_parse_info(const char *data, int len);

static uint64_t xlink_time(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

static void xlink_extract_analog(const struct dev_channel* ch, unsigned framelen, float* outbuff, const char* src, unsigned proceed)
{
	uint64_t			buf64[CONVERSION_BUFF_SIZE];
	unsigned			j, shift;
	const float		scale = ch->scale;
	const uint8_t*	s = (const void *)&src[ch->frameoffset];
	const int		be = ch->isbigendian;

	if(ch->isfloat)
	{
		const int af = ch->isarmfloat;
		union { float f; uint32_t u; } uf;
		union { double d; uint64_t u; } ud;
		unsigned u16, fsign, fmantissa, fexp, clz;
		switch(ch->bits)
		{
		case sizeof(uint16_t) * 8:
			for(j = 0 ; j < proceed ; ++j, s += framelen)
			{
				u16 = be ? GUINT32_FROM_BE(*(const int32_t *)s) : GUINT32_FROM_LE(*(const int32_t *)s);
				fsign = u16 >> 15;
				fmantissa = u16 & 0x3FF;
				fexp = (u16 >> 10) & 0x1F;
				uf.u = fsign << 31;
				if(!fexp)
				{	// zero, -zero, subnormal
					if(fmantissa)
					{	// subnormal, convert to normalized
						clz = __builtin_clz(fmantissa) - 21;
						fmantissa = (fmantissa << clz) & 0x3FF;
						fexp = (127 - 14) - clz;
						uf.u |= (fexp << 23) | (fmantissa << 13);
					}
				} else if(!af && (fexp == 31))
				{	// nan, inf and not armfloat
					uf.u |= (0xFF << 23) | (fmantissa << 13);
				} else
				{	// normalized
					fexp += 127 - 15;
					uf.u |= (fexp << 23) | (fmantissa << 13);
				}
				outbuff[j] = uf.f * scale;
			}
			break;
		case sizeof(float) * 8:
			for(j = 0 ; j < proceed ; ++j, s += framelen)
			{
				uf.u       = be ? GUINT32_FROM_BE(*(const int32_t *)s) : GUINT32_FROM_LE(*(const int32_t *)s);
				outbuff[j] = uf.f * scale;
			}
			break;
		case sizeof(double) * 8:
			for(j = 0 ; j < proceed ; ++j, s += framelen)
			{
				ud.u       = be ? GUINT64_FROM_BE(*(const int64_t *)s) : GUINT64_FROM_LE(*(const int64_t *)s);
				outbuff[j] = ud.d * scale;
			}
			break;
		}
	} else if(ch->bits <= 64)
	{
		shift = 64 - ch->bits;
		for(j = 0 ; j < proceed ; ++j, s += framelen)
			buf64[j] = be ? GUINT64_FROM_BE(*(const uint64_t *)s) : (GUINT64_FROM_LE(*(const uint64_t *)s) << shift);
		if(ch->isunsigned)
		{
			for(j = 0 ; j < proceed ; ++j)
				outbuff[j] = (buf64[j] >> shift) * scale;
		} else
		{
			for(j = 0 ; j < proceed ; ++j)
				outbuff[j] = ((int64_t)buf64[j] >> shift) * scale;
		}
	}
}

static void xlink_extract_digital(const struct dev_channel* ch, unsigned framelen, uint32_t* outbuff, const char* src, unsigned proceed)
{
	unsigned			j;
	const unsigned	set = 1 << ch->channel->index;
	const unsigned	mask = 1 << ch->bits;
	const uint8_t*	s = (const void *)&src[ch->frameoffset];

	for(j = 0 ; j < proceed ; ++j, s += framelen)
	{
		if(*s & mask)
			outbuff[j] |= set;
	}
}

static unsigned xlink_digital_trigger(struct dev_channel* ch, const uint32_t* buff, int trig_delay, unsigned proceed)
{
	unsigned haslast = ch->haslast, lastone = ch->lastone;
	unsigned i, bit, ok;

	for(i = 0 ; i < proceed ; ++i, --trig_delay)
	{
		bit = (buff[i] != 0);
		ok = 0;
		switch(ch->trigger)
		{
		case SR_TRIGGER_ZERO:
			ok = !bit;
			break;
		case SR_TRIGGER_ONE:
			ok = bit;
			break;
		case SR_TRIGGER_RISING:
			ok = haslast && !lastone && bit;
			break;
		case SR_TRIGGER_FALLING:
			ok = haslast && lastone && !bit;
			break;
		case SR_TRIGGER_EDGE:
			ok = haslast && (lastone != bit);
			break;
		}
		haslast = 1;
		lastone = bit;
		if(ok && (trig_delay <= 0))
			break;
	}
	ch->haslast = haslast;
	ch->lastone = lastone;
	return i;
}

static unsigned xlink_analog_trigger(struct dev_channel* ch, const float* buff, int trig_delay, unsigned proceed)
{
	const float trigval = ch->trigval;
	unsigned haslast = ch->haslast, lastone = ch->lastone;
	unsigned i, bit, ok;

	for(i = 0 ; i < proceed ; ++i, --trig_delay)
	{
		bit = (buff[i] >= trigval);
		ok = 0;
		switch(ch->trigger)
		{
		case SR_TRIGGER_RISING:
			ok = haslast && !lastone && bit;
			break;
		case SR_TRIGGER_FALLING:
			ok = haslast && lastone && !bit;
			break;
		case SR_TRIGGER_EDGE:
			ok = haslast && (lastone != bit);
			break;
		case SR_TRIGGER_UNDER:
			ok = !bit;
			break;
		case SR_TRIGGER_OVER:
			ok = bit;
			break;
		}
		haslast = 1;
		lastone = bit;
		if(ok && (trig_delay <= 0))
			break;
	}
	ch->haslast = haslast;
	ch->lastone = lastone;
	return i;
}

SR_PRIV int xlink_net_receive_data(int fd, int revents, void *cb_data)
{
	const struct sr_dev_inst*	sdi;
	struct dev_context*			devc;

	if (!(sdi = cb_data) || !(devc = sdi->priv))
		return TRUE;
	if(revents == G_IO_IN)
	{
		const struct dev_info*     di = devc->di;
		struct dev_channel*  		ch;
		struct sr_datafeed_packet 	packet;
		struct sr_datafeed_analog	analog;
		struct sr_datafeed_logic 	logic;
		struct sr_analog_encoding	encoding;
		struct sr_analog_meaning	meaning;
		struct sr_analog_spec		spec;
		int								len, logics, trigger;
		unsigned							samples, proceed, framelen, triggered;
		const char*						src;
		union
		{
			float							f[CONVERSION_BUFF_SIZE];
			uint32_t						u32[CONVERSION_BUFF_SIZE];
		} buf;
		

		if(devc->buffer_size < devc->buffer_maxsize)
		{	/* read more */
			len = recv(fd, devc->buffer + devc->buffer_size, devc->buffer_maxsize - devc->buffer_size, 0);
			if(len < 0)
			{
				sr_err("Receive error: %s", g_strerror(errno));
				return SR_ERR;
			}
			if(len == 0)
			{
				sr_info("Closed with received %llu samples", devc->recv_samples);
				goto do_stop;
			}
			devc->buffer_size += len;
		}
		trigger = 0;
		framelen = di->framelen;
		samples = devc->buffer_size / framelen;
		src = devc->buffer;
		while(samples && !trigger)
		{
			proceed = MIN(CONVERSION_BUFF_SIZE, samples);
			proceed = MIN(devc->limit_samples - devc->recv_samples, proceed);
			if(!proceed)
				break;
			/* proceed triggers */
			for(ch = di->digital ; ch && proceed ; ch = ch->next)
			{
				if(ch->channel && ch->channel->enabled && ch->trigger)
				{
					memset(&buf, 0, sizeof(buf));
					xlink_extract_digital(ch, framelen, buf.u32, src, proceed);
					triggered = xlink_digital_trigger(ch, buf.u32, devc->trigger_delay, proceed);
					if(triggered != proceed)
					{	/* trigger found */
						proceed = triggered;
						trigger = 1;
					}
				}
			}
			for(ch = di->analog ; ch && proceed ; ch = ch->next)
			{
				if(ch->channel && ch->channel->enabled && ch->trigger)
				{
					memset(&buf, 0, sizeof(buf));
					xlink_extract_analog(ch, framelen, buf.f, src, proceed);
					triggered = xlink_analog_trigger(ch, buf.f, devc->trigger_delay, proceed);
					if(triggered != proceed)
					{	/* trigger found */
						proceed = triggered;
						trigger = 1;
					}
				}
			}
			if(!proceed)
				break;
			/* push digital data */
			memset(&buf, 0, sizeof(buf));
			for(ch = di->digital, logics = 0 ; ch ; ch = ch->next)
			{
				if(!ch->channel || !ch->channel->enabled)
					continue;
				logics += 1;
				xlink_extract_digital(ch, framelen, buf.u32, src, proceed);
			}
			if(logics)
			{
				logic.data = buf.u32;
				logic.unitsize = sizeof(buf.u32[0]);
				logic.length = proceed * logic.unitsize;
				packet.type = SR_DF_LOGIC;
				packet.payload = &logic;
				sr_session_send(sdi, &packet);
			}
			/* push analog data */
			for(ch = di->analog ; ch ; ch = ch->next)
			{
				if(!ch->channel || !ch->channel->enabled)
					continue;
				sr_analog_init(&analog, &encoding, &meaning, &spec, 0);
				meaning.mq = ch->mq;
				meaning.unit = ch->unit;
				analog.data = buf.f;
				analog.num_samples = proceed;
				packet.type = SR_DF_ANALOG;
				packet.payload = &analog;
				analog.meaning->channels = g_slist_append(NULL, ch->channel);
				/* unpack data */
				memset(&buf, 0, sizeof(buf));
				xlink_extract_analog(ch, framelen, buf.f, src, proceed);
				sr_session_send(sdi, &packet);
				g_slist_free(analog.meaning->channels);
			}
			samples -= proceed;
			src += proceed * framelen;
			devc->recv_samples += proceed;
		}
		proceed = (devc->buffer_size / framelen) - samples;
		devc->buffer_size -= proceed * framelen;
		memmove(devc->buffer, devc->buffer + (proceed * framelen), devc->buffer_size);
		if(trigger)
		{	/* send trigger */
			devc->trigger_delay = devc->trigger_holdoff;
			std_session_send_df_trigger(sdi);
		} else
		{	/* decrement trigger delay */
			devc->trigger_delay -= MIN(devc->trigger_delay, proceed);
		}
		if(devc->recv_samples >= devc->limit_samples)
			goto do_stop;
	}
	if(devc->recv_samples >= devc->limit_samples)
	{	/* completed - Send EOA Packet, stop polling */
	do_stop:
		std_session_send_df_end(sdi);
		sr_session_source_remove_pollfd(sdi->session, &devc->pollfd);
		xlink_net_stop(devc);
	}
	return TRUE;
}

SR_PRIV int xlink_net_start(struct dev_context *devc)
{
	int fd, len;
	char* end;
	struct dev_info* di;
	struct dev_channel* ch;
	uint64_t from;

	if(devc->socket >= 0)
		xlink_net_stop(devc);
	if(!devc->di)
		return SR_ERR;
	fd = socket(devc->di->addr->ai_family, devc->di->addr->ai_socktype, devc->di->addr->ai_protocol);
	if(fd < 0)
		return SR_ERR;
	for(from = xlink_time() ; ;)
	{
		if(!connect(fd, devc->di->addr->ai_addr, devc->di->addr->ai_addrlen))
			break;
		if(errno != ECONNREFUSED)
			goto on_err;
		if((int64_t)(xlink_time() - from) > WAIT_TIME)
		{
			sr_err("timeout waiting for connecting");
			goto on_err;
		}
		usleep(10000); /* 10ms */
	}
	/* Read-out header */
	devc->buffer_size = 0;
	for(from = xlink_time() ; ;)
	{
		if((len = read(fd, &devc->buffer[devc->buffer_size], MAX_DESCRIPTION_SIZE - devc->buffer_size)) <= 0)
			goto on_err;
		devc->buffer_size += len;
		if((end = memchr(devc->buffer, 0, devc->buffer_size)) != NULL)
			break;
		if((int64_t)(xlink_time() - from) > WAIT_TIME)
		{
			sr_err("timeout waiting for connecting");
			goto on_err;
		}
		usleep(10000); /* 10ms */
	}
	if((di = xlink_net_parse_info(devc->buffer, end - devc->buffer)) == NULL)
		goto on_err;
	xlink_net_free_info(di);
	devc->buffer_size = devc->buffer_size - (end - devc->buffer + 1);
	memmove(devc->buffer, end + 1, devc->buffer_size);
	devc->socket = fd;
	devc->recv_samples = 0;
	devc->trigger_delay = 0;
	for(ch = devc->di->analog ; ch ; ch = ch->next)
		ch->haslast = 0;
	for(ch = devc->di->digital ; ch ; ch = ch->next)
		ch->haslast = 0;
	return SR_OK;
on_err:
	close(fd);
	return SR_ERR;
}

SR_PRIV int xlink_net_stop(struct dev_context *devc)
{
	if(devc->socket >= 0)
	{
		close(devc->socket);
		devc->socket = -1;
	}
	return SR_OK;
}

///////////////////////////////////////////////////////////////////////////////////////////////////

SR_PRIV void xlink_net_free_info(struct dev_info *info)
{
	if(info)
	{
		struct dev_channel *ch, *next;
		for(ch = info->analog ; ch ; ch = next)
		{
			next = ch->next;
			g_free(ch->name);
			g_free(ch);
		}
		for(ch = info->digital ; ch ; ch = next)
		{
			next = ch->next;
			g_free(ch->name);
			g_free(ch);
		}
		g_free(info->name);
		freeaddrinfo(info->addresses);
		g_free(info);
	}
}

static struct dev_info* xlink_net_parse_info(const char* buf, int len)
{
	const char mgroup[] = "xlink-net-1.0";
	GKeyFile* kf;
	GError* gerr = NULL;
	char** groups = NULL;
	struct dev_info* di = NULL;
	char* txt = NULL;
	struct dev_channel* ch;
	struct dev_channel* lastanalog;
	struct dev_channel* lastdigital;
	const struct dev_channel* test;
	unsigned digitals;
	const char* dsc;
	unsigned i, from, to, bit;
	char cend;

	kf = g_key_file_new();
	if(!g_key_file_load_from_data(kf, buf, len, 0, &gerr))
		goto on_err;
	if((groups = g_key_file_get_groups(kf, NULL)) == NULL)
		goto on_err;
	di = g_new0(struct dev_info, 1);
	di->sr = g_key_file_get_integer(kf, mgroup, "sr", &gerr);
	if(gerr)
		goto on_err;
	if(!di->sr || (di->sr > 10000000))
	{
		sr_err("invalid sr: %u", (unsigned)di->sr);
		goto on_err;
	}
	di->framelen = g_key_file_get_integer(kf, mgroup, "framelen", &gerr);
	if(gerr)
		goto on_err;
	if(!di->framelen || (di->framelen > 1024))
	{
		sr_err("invalid framelen: %u", di->framelen);
		goto on_err;
	}
	di->name = g_key_file_get_string(kf, mgroup, "name", NULL);
	if(!di->name)
		di->name = g_strdup(mgroup);
	lastdigital = NULL;
	lastanalog = NULL;
	digitals = 0;
	for(i = 0 ; groups[i] ; ++i)
	{
		dsc = groups[i];
		if(!strcmp(dsc, mgroup))
			continue;
		ch = g_new0(struct dev_channel, 1);
		ch->name = g_key_file_get_string(kf, dsc, "name", NULL);
		ch->scale = 1;
		if(!ch->name)
			ch->name = g_strdup(dsc);
		if(sscanf(dsc, "%d-%d%c", &from, &to, &cend) == 2)
		{	/* analog channel */
			sr_info("Found analog channel: %d, %s", i, ch->name);
			for(test = di->analog ; test ; test = test->next)
			{
				if(!strcmp(test->name, ch->name))
				{
					sr_err("duplicate channel name: %s", ch->name);
					goto on_err;
				}
			}
			if((from >= di->framelen) || (to >= di->framelen) || (from == to))
			{
				sr_err("invalid analog descriptor: %s", dsc);
				goto on_err;
			}
			if(g_key_file_has_key(kf, dsc, "scale", NULL))
			{
				ch->scale = g_key_file_get_double(kf, dsc, "scale", &gerr);
				if(gerr)
					goto on_err;
			}
			txt = g_key_file_get_string(kf, dsc, "mq", &gerr);
			if(gerr)
				goto on_err;
			if(!strcmp(txt, "voltage"))
			{
				ch->mq = SR_MQ_VOLTAGE;
				ch->unit = SR_UNIT_VOLT;
			} else if(!strcmp(txt, "current"))
			{
				ch->mq = SR_MQ_CURRENT;
				ch->unit = SR_UNIT_AMPERE;
			} else if(!strcmp(txt, "duty"))
			{
				ch->mq = SR_MQ_DUTY_CYCLE;
				ch->unit = SR_UNIT_PERCENTAGE;
			} else
			{
				sr_err("invalid mq: %s", txt);
				goto on_err;
			}
			g_free(txt);
			txt = NULL;
			txt = g_key_file_get_string(kf, dsc, "encoding", &gerr);
			if(gerr)
				goto on_err;
			if(!strcmp(txt, "signed"))
				ch->isunsigned = 0;
			else if(!strcmp(txt, "unsigned"))
				ch->isunsigned = 1;
			else if(!strcmp(txt, "float"))
				ch->isfloat = 1;
			else if(!strcmp(txt, "armfloat"))
				ch->isfloat = ch->isarmfloat = 1;
			else
			{
				sr_err("invalid encoding: %s", txt);
				goto on_err;
			}
			g_free(txt);
			txt = NULL;
			if(from < to)
			{	/* little endian */
				ch->isbigendian = 0;
				ch->frameoffset = from;
				bit = (to - from + 1) * 8;
			} else
			{	/* big endian */
				ch->isbigendian = 1;
				ch->frameoffset = to;
				bit = (from - to + 1) * 8;
			}
			ch->bits = bit;
			if(g_key_file_has_key(kf, dsc, "bits", NULL))
			{
				ch->bits = g_key_file_get_integer(kf, dsc, "bits", &gerr);
				if(gerr)
					goto on_err;
				if(ch->bits > bit)
				{
					sr_err("Invalid bits value: %u", ch->bits);
					goto on_err;
				}
			}
			if(ch->bits > 64)
			{
				sr_err("field (%s) is too long: %u", dsc, bit);
				goto on_err;
			}
			if(lastanalog)
				lastanalog->next = ch;
			else
				di->analog = ch;
			lastanalog = ch;
		} else if(sscanf(dsc, "%d.%d%c", &from, &bit, &cend) == 2)
		{  /* digital channel */
			sr_info("Found digital channel: %d, %s", i, ch->name);
			if(digitals >= 32)
			{
				sr_err("too many logic channels, max 32");
				goto on_err;
			}
			if((from >= di->framelen) || (bit >= 8))
			{
				sr_err("invalid digital descriptor: %s", dsc);
				goto on_err;
			}
			ch->frameoffset = from;
			ch->bits = bit;
			if(lastdigital)
				lastdigital->next = ch;
			else
				di->digital = ch;
			lastdigital = ch;
			digitals += 1;
		} else
		{
			sr_err("invalid channel description: %s", dsc);
			goto on_err;
		}
	}
	g_strfreev(groups);
	g_key_file_free(kf);
	return di;
on_err:
	sr_err("xlink_net_parse_info error: %s, %s", txt, gerr ? gerr->message : NULL);
	g_free(txt);
	xlink_net_free_info(di);
	g_strfreev(groups);
	g_key_file_free(kf);
	return NULL;
}

SR_PRIV struct dev_info* xlink_net_load_info(const char* addr, const char* port)
{
	struct dev_info* di = NULL;
	if(addr && port)
	{
		struct addrinfo hints = {};
		struct addrinfo *results, *res;
		int err, fd, len, off;
		char buff[MAX_DESCRIPTION_SIZE];
		char* end;
		uint64_t from;

		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		sr_info("Connecting to %s:%s", addr, port);
		if((err = getaddrinfo(addr, port, &hints, &results)) != 0)
		{
			sr_err("Address lookup failed: %s:%s: %s", addr, port, gai_strerror(err));
			return NULL;
		}
		for(res = results; res; res = res->ai_next)
		{
			if((fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
				continue;
			if(connect(fd, res->ai_addr, res->ai_addrlen) == 0)
			{
				sr_info("Connected to %s:%s", addr, port);
				off = 0;
				for(from = xlink_time() ; ;)
				{
					if((len = read(fd, &buff[off], MAX_DESCRIPTION_SIZE - off)) <= 0)
						break;
					off += len;
					if((end = memchr(buff, 0, off)) != NULL)
					{
						len = end - buff;
						sr_info("Header found, %d size", len);
						if((di = xlink_net_parse_info(buff, len)) != NULL)
						{
							di->addresses = results;
							di->addr = res;
							close(fd);
							return di;
						}
					}
					if((int64_t)(xlink_time() - from) > WAIT_TIME)
						break;
					usleep(10000); /* 10ms */
				}
			}
			close(fd);
		}
		freeaddrinfo(results);
	}
	return NULL;
}
