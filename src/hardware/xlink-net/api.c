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
#include "protocol.h"

static struct sr_dev_driver xlink_net_driver_info;

static const uint32_t scanopts[] = {
	SR_CONF_CONN,
};

static const uint32_t drvopts[] = {
	SR_CONF_OSCILLOSCOPE,
	SR_CONF_LOGIC_ANALYZER
};

static const uint32_t devopts[] = {
	SR_CONF_CONTINUOUS,
	SR_CONF_LIMIT_SAMPLES | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_SAMPLERATE | SR_CONF_GET,
	SR_CONF_TRIGGER_MATCH | SR_CONF_LIST,
	SR_CONF_HOLDOFF | SR_CONF_GET | SR_CONF_SET,
	/*SR_CONF_TRIGGER_SOURCE | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_TRIGGER_SLOPE |  SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_TRIGGER_LEVEL | SR_CONF_GET | SR_CONF_SET,*/
};

static const int32_t trigger_matches[] = {
	SR_TRIGGER_ZERO,
	SR_TRIGGER_ONE,
	SR_TRIGGER_RISING,
	SR_TRIGGER_FALLING,
	SR_TRIGGER_EDGE,
	SR_TRIGGER_OVER,
	SR_TRIGGER_UNDER
};

static const char *trigger_slopes[] = {
	"r", "f",
};

static enum sr_trigger_matches trigger_slope_matches[] = {
	SR_TRIGGER_RISING, SR_TRIGGER_FALLING,
};

static GSList *scan(struct sr_dev_driver *di, GSList *options)
{
	GSList *l;
	struct sr_config *src;
	struct sr_dev_inst *sdi;
	struct dev_context *devc;
	struct dev_channel* ch;
	const char *conn;
	gchar **params;
	int i;

	conn = NULL;
	for (l = options; l; l = l->next)
	{
		src = l->data;
		if (src->key == SR_CONF_CONN)
			conn = g_variant_get_string(src->data, NULL);
	}
	if (!conn)
	{
		sr_err("No SR_CONF_CONN specified");
		return NULL;
	} else
	{
		params = g_strsplit(conn, "/", 0);
		if (!params || !params[1] || !params[2])
		{
			sr_err("Invalid Parameters.");
			g_strfreev(params);
			return NULL;
		}
		if (g_ascii_strncasecmp(params[0], "tcp", 3))
		{
			sr_err("Only TCP (tcp-raw) protocol is currently supported.");
			g_strfreev(params);
			return NULL;
		}
	}
	sdi						= g_new0(struct sr_dev_inst, 1);
	sdi->status				= SR_ST_INACTIVE;
	sdi->model				= g_strdup("xlink-net");
	sdi->version			= g_strdup("1.0");
	devc						= g_new0(struct dev_context, 1);
	devc->socket			= -1;
	devc->limit_samples	= 10000000;
	devc->buffer_maxsize	= 128 * 1024;
	devc->trigger_holdoff = 64;
	devc->trigger_slope  = SR_TRIGGER_RISING;
	devc->di					= xlink_net_load_info(params[1], params[2]);
	if(devc->di)
		sr_info("xlink-net device found at %s : %s", params[1], params[2]);
	g_strfreev(params);
	if(!devc->di)
		goto err_free;
	for(i = 0, ch = devc->di->digital ; ch ; ch = ch->next, ++i)
		ch->channel = sr_channel_new(sdi, i, SR_CHANNEL_LOGIC, TRUE, ch->name);
	for(ch = devc->di->analog ; ch ; ch = ch->next, ++i)
		ch->channel = sr_channel_new(sdi, i, SR_CHANNEL_ANALOG, TRUE, ch->name);
	sdi->priv = devc;
	return std_scan_complete(di, g_slist_append(NULL, sdi));

err_free:
	g_free(sdi->model);
	g_free(sdi->version);
	g_free(devc);
	g_free(sdi);

	return NULL;
}

static int dev_open(struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;

	devc->buffer = g_realloc(devc->buffer, devc->buffer_maxsize);
	return SR_OK;
}

static int dev_close(struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;
	xlink_net_stop(devc);
	return SR_OK;
}

static int config_get(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	struct dev_context *devc = sdi->priv;
	unsigned i;

	(void)cg;

	switch (key) {
	case SR_CONF_LIMIT_SAMPLES:
		if(!devc)
			return SR_ERR_ARG;
		*data = g_variant_new_uint64(devc->limit_samples);
		break;
	case SR_CONF_SAMPLERATE:
		if(!devc)
			return SR_ERR_ARG;
		*data = g_variant_new_uint64(devc->di->sr);
		break;
	case SR_CONF_TRIGGER_SOURCE:
		if(!devc)
			return SR_ERR_ARG;
		*data = g_variant_new_string(devc->trigger_source ? devc->trigger_source->name : "");
		break;
	case SR_CONF_TRIGGER_SLOPE:
		if(!devc)
			return SR_ERR_ARG;
		for(i = 0 ; i < ARRAY_SIZE(trigger_slopes) ; ++i)
		{
			if(devc->trigger_slope == trigger_slope_matches[i])
			{
				*data = g_variant_new_string(trigger_slopes[i]);
				return SR_OK;
			}
		}
		*data = g_variant_new_string("");
		break;
	case SR_CONF_TRIGGER_LEVEL:
		if(!devc)
			return SR_ERR_ARG;
		*data = g_variant_new_double(devc->trigger_level);
		break;
	case SR_CONF_HOLDOFF:
		if(!devc)
			return SR_ERR_ARG;
		*data = g_variant_new_uint64(devc->trigger_holdoff);
		break;
	default:
		return SR_ERR_NA;
	}

	return SR_OK;
}

static void clear_helper(struct dev_context *devc)
{
	g_free(devc->buffer);
	xlink_net_free_info(devc->di);
}

static int dev_clear(const struct sr_dev_driver *di)
{
	return std_dev_clear_with_callback(di, (std_dev_clear_callback)clear_helper);
}

static int config_set(uint32_t key, GVariant *data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	struct dev_context *devc = sdi->priv;
	struct dev_channel* ch;
	const char* str;
	unsigned i;

	(void)cg;

	switch (key) {
	case SR_CONF_LIMIT_SAMPLES:
		if(!devc)
			return SR_ERR_ARG;
		devc->limit_samples = g_variant_get_uint64(data);
		break;
	case SR_CONF_TRIGGER_SOURCE:
		if(!devc)
			return SR_ERR_ARG;
		devc->trigger_source = NULL;
		if((str = g_variant_get_string(data, NULL)) != NULL)
		{
			for(ch = devc->di->analog ; ch ; ch = ch->next)
			{
				if(!strcmp(ch->name, str))
				{
					devc->trigger_source = ch;
					return SR_OK;
				}
			}
			return SR_ERR_ARG;
		}
		break;
	case SR_CONF_TRIGGER_SLOPE:
		str = g_variant_get_string(data, NULL);
		if(!devc || !str)
			return SR_ERR_ARG;
		for(i = 0 ; i < ARRAY_SIZE(trigger_slopes) ; ++i)
		{
			if(!strcmp(str, trigger_slopes[i]))
			{
				devc->trigger_slope = trigger_slope_matches[i];
				return SR_OK;
			}
		}
		return SR_ERR_ARG;
	case SR_CONF_TRIGGER_LEVEL:
		if(!devc)
			return SR_ERR_ARG;
		devc->trigger_level = g_variant_get_double(data);
		break;
	case SR_CONF_HOLDOFF:
		if(!devc)
			return SR_ERR_ARG;
		devc->trigger_holdoff = g_variant_get_uint64(data);
		break;
	default:
		return SR_ERR_NA;
	}

	return SR_OK;
}

static int config_list(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	struct dev_context *devc = sdi->priv;
	const struct dev_channel* ch;
	const char** str;
	unsigned len;
	switch (key) {
	case SR_CONF_SCAN_OPTIONS:
	case SR_CONF_DEVICE_OPTIONS:
		return STD_CONFIG_LIST(key, data, sdi, cg, scanopts, drvopts, devopts);
	case SR_CONF_SAMPLERATE:
		if(!devc)
			return SR_ERR_ARG;
		*data = std_gvar_samplerates(&devc->di->sr, 1);
		break;
	case SR_CONF_TRIGGER_MATCH:
		*data = std_gvar_array_i32(ARRAY_AND_SIZE(trigger_matches));
		break;
	case SR_CONF_TRIGGER_SOURCE:
		if(!devc)
			return SR_ERR_ARG;
		for(ch = devc->di->analog, len = 0 ; ch ; ch = ch->next, ++len);
		str = g_new0(const char *, len + 1);
		for(ch = devc->di->analog, len = 0 ; ch ; ch = ch->next, ++len)
			str[len] = ch->name;
		*data = g_variant_new_strv(str, len);
		g_free(str);
		break;
	case SR_CONF_TRIGGER_SLOPE:
		*data = g_variant_new_strv(ARRAY_AND_SIZE(trigger_slopes));
		break;
	default:
		return SR_ERR_NA;
	}
	return SR_OK;
}

static void dev_set_trigger(struct dev_channel* ch, const struct sr_trigger* trigger)
{
	ch->trigger = 0;
	if(trigger && trigger->stages)
	{	/* only one stage supported */
		const struct sr_trigger_stage* stage = trigger->stages->data;
		GSList* l = stage->matches;
		for(; l ; l = l->next)
		{
			const struct sr_trigger_match* match = l->data;
			if(match->channel == ch->channel)
			{
				ch->trigger = match->match;
				ch->trigval = match->value;
			}
		}
	}
}

static int dev_acquisition_start(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;
	struct dev_channel *ch;
	const struct sr_trigger *trigger;
	int err;

	trigger = sr_session_trigger_get(sdi->session);
	/* set triggers */
	for(ch = devc->di->analog ; ch ; ch = ch->next)
		dev_set_trigger(ch, trigger);
	for(ch = devc->di->digital ; ch ; ch = ch->next)
		dev_set_trigger(ch, trigger);

	std_session_send_df_header(sdi);
	/* Trigger and add poll on file */
	err = xlink_net_start(devc);
	if(err != SR_OK)
		return err;
	/* Set fd and local attributes */
	devc->pollfd.fd = devc->socket;
	devc->pollfd.events = G_IO_IN;
	devc->pollfd.revents = 0;

	sr_session_source_add_pollfd(sdi->session, &devc->pollfd,
			200, xlink_net_receive_data,
			(void *)sdi);

	return SR_OK;
}

static int dev_acquisition_stop(struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;

	/* Remove session source and send EOT packet */
	sr_session_source_remove_pollfd(sdi->session, &devc->pollfd);
	std_session_send_df_end(sdi);
	xlink_net_stop(devc);

	return SR_OK;
}

static struct sr_dev_driver xlink_net_driver_info = {
	.name = "xlink-net",
	.longname = "xlink-net",
	.api_version = 1,
	.init = std_init,
	.cleanup = std_cleanup,
	.scan = scan,
	.dev_list = std_dev_list,
	.dev_clear = dev_clear,
	.config_get = config_get,
	.config_set = config_set,
	.config_list = config_list,
	.dev_open = dev_open,
	.dev_close = dev_close,
	.dev_acquisition_start = dev_acquisition_start,
	.dev_acquisition_stop = dev_acquisition_stop,
	.context = NULL,
};
SR_REGISTER_DEV_DRIVER(xlink_net_driver_info);
