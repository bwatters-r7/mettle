/**
 * Copyright 2015 Rapid7
 * @brief Core API calls
 * @file tlv_coreapi.c
 */

#include "channel.h"
#include "log.h"
#include "tlv.h"

#include <mettle.h>

static struct tlv_packet *machine_id(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	return tlv_packet_add_str(p, TLV_TYPE_MACHINE_ID, mettle_get_fqdn(m));
}

static void add_method(const char *method, void *arg)
{
	struct tlv_packet **p = arg;
	*p = tlv_packet_add_str(*p, TLV_TYPE_STRING, method);
}

static struct tlv_packet *enumextcmd(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	const char *extension = tlv_packet_get_str(ctx->req, TLV_TYPE_STRING);
	if (extension == NULL) {
		return NULL;
	}

	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	tlv_dispatcher_iter_extension_methods(td, extension, add_method, &p);
	return p;
}

static struct tlv_packet *core_shutdown(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);

	void (*nada)(void) = NULL;
	nada();

	return p;
}

static struct tlv_packet *core_channel_eof(struct tlv_handler_ctx *ctx)
{
	log_debug("in core_channel_eof");
	uint32_t channel_id = 0;
	tlv_packet_get_u32(ctx->req, TLV_TYPE_CHANNEL_ID, &channel_id);
	struct tlv_packet *p;
	if (channel_id == 0){
		/*
		 * framework sends periodic eofs for channel id 0
		 * as a bad keep-alive; just accept them and exit
		 */
		log_debug("got framework eof keep-alive");
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	}else{
		log_debug("got eof for channel %d", channel_id);
		/*
		 * process the eof
		 */
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	}
	return p;

}
static struct tlv_packet *core_channel_open(struct tlv_handler_ctx *ctx)
{
	log_debug("here");
	struct tlv_packet *p;
	struct open_channel_entry* channel = core_channel_new(ctx);
	uint32_t channel_id = 0;
	if (-1 == get_channel_id(channel, &channel_id)){
		p = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}else{
		log_debug("sending back channel_id %u", channel_id);
		p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
		p = tlv_packet_add_u32(p, TLV_TYPE_CHANNEL_ID, channel_id);
	}
	return p;
}
static struct tlv_packet *core_channel_read(struct tlv_handler_ctx *ctx)
{
	uint32_t channel_id = 0;
	log_debug("core_channel_read");
	if(-1 == tlv_packet_get_u32(ctx->req, TLV_TYPE_CHANNEL_ID, &channel_id)){
		log_debug("failed to get read channel id");
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}
	struct open_channel_entry* channel = get_open_channel(ctx, channel_id);
	if (channel ==NULL){
		log_debug("no channel found with id %u", channel_id);
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}
	return channel_dispatch_read(ctx, channel);

}

static struct tlv_packet *core_channel_write(struct tlv_handler_ctx *ctx)
{
	uint32_t channel_id = 0;
	log_debug("core_channel_write");
	if(-1 == tlv_packet_get_u32(ctx->req, TLV_TYPE_CHANNEL_ID, &channel_id)){
		log_debug("failed to get write channel id");
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}
	struct open_channel_entry* channel = get_open_channel(ctx, channel_id);
	if (channel ==NULL){
		log_debug("no channel found with id %u", channel_id);
		return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	}
	return channel_dispatch_write(ctx, channel);

}

void tlv_register_coreapi(struct mettle *m, struct tlv_dispatcher *td)
{
	tlv_dispatcher_add_handler(td, "core_enumextcmd", 	enumextcmd, m);
	tlv_dispatcher_add_handler(td, "core_machine_id", 	machine_id, m);
	tlv_dispatcher_add_handler(td, "core_shutdown",  	core_shutdown, m);
	tlv_dispatcher_add_handler(td, "core_channel_open", core_channel_open, m);
	tlv_dispatcher_add_handler(td, "core_channel_eof", 	core_channel_eof, m);
	tlv_dispatcher_add_handler(td, "core_channel_read", core_channel_read, m);
	tlv_dispatcher_add_handler(td, "core_channel_write", core_channel_write, m);
}
