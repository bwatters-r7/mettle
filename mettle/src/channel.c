#include <limits.h>

#include "channel.h"
#include "log.h"
#include "uthash.h"

int tlv_register_default_channel_dispatchers(struct mettle *m)
{
	log_debug("registering stdapi_fs_file_type in mettle object %p", m);
	tlv_register_channel_handlers(m,
			"stdapi_fs_file",
			fs_file_initialize,
			fs_file_read,
			fs_file_write,
			fs_file_interact,
			fs_file_close);
	return 0;
}

struct channel_type_entry* tlv_register_channel_handlers(struct mettle *m,
		char* str_type,
		channel_initializer channel_initialize,
		channel_handler channel_read,
		channel_handler channel_write,
		channel_handler channel_interact,
		channel_handler channel_close)
{
	log_debug("tlv_register_channel_handlers");
	log_debug("mettle address = %p", m);
	struct channel_type_entry **type_table = mettle_get_channel_type_table(m);
	struct channel_type_entry *type_entry = NULL;
	struct channel_handlers *handler_entry;
	/*
	 * try to find it
	 */
	handler_entry = get_channel_handlers(m, str_type);
	if (handler_entry == NULL){
		uint32_t str_len = strlen(str_type)+1;
		char* new_str = calloc(1, str_len);
		handler_entry = calloc(1, sizeof(struct channel_handlers));
		type_entry = calloc(1, sizeof(struct channel_type_entry));
		strncpy(new_str, str_type, str_len);
		/*
		 * are all our structs valid?
		 */
		if ((new_str == NULL) ||
				(handler_entry == NULL) ||
				(type_entry == NULL)){
			return NULL;
		}
		type_entry->handlers=handler_entry;
		type_entry->str_type = new_str;
		HASH_ADD_KEYPTR(hh, *type_table, type_entry->str_type, strlen(type_entry->str_type), type_entry);
	}
	handler_entry->initialize = channel_initialize;
	handler_entry->read = channel_read;
	handler_entry->write = channel_write;
	handler_entry->interact = channel_interact;
	handler_entry->close = channel_close;
	return type_entry;
}


struct channel_handlers* get_channel_handlers(struct mettle *m, const char* str_type)
{
	log_debug("in get_channel_handlers");
	log_debug("looking for %s", str_type);
	struct channel_type_entry **type_table = mettle_get_channel_type_table(m);
	struct channel_type_entry *type_entry;
	HASH_FIND_STR(*type_table, str_type, type_entry);
	if (type_entry != NULL)
		return type_entry->handlers;
	return NULL;
}

int add_channel(struct mettle *m, struct open_channel_entry* channel_in)
{
	/*
	 * channel_id 0 used by framework for keep-alive messages
	 * this should be changed on the framework side.
	 * until then, we start looking for open spots at 1
	 * rather than 0
	 */
	struct open_channel_entry **channel_table = mettle_get_channel_instances(m);
	log_debug("mettle location = %p", m);
	log_debug("channel_table location = %p", *channel_table);
	struct open_channel_entry *channel_entry;
	log_debug("here");
	for(uint32_t i = 1; i <= INT_MAX; i++){
		HASH_FIND_INT(*channel_table, &i, channel_entry);
		if (channel_entry == NULL){
			channel_in->channel_id = i;
			HASH_ADD_INT(*channel_table, channel_id, channel_in);
			log_debug("channel_table location = %p", *channel_table);
			log_debug("channel %d inserted into open_channels", channel_in->channel_id);
			struct open_channel_entry *test_entry;
			HASH_FIND_INT(*channel_table, &channel_in->channel_id, test_entry);
			if (test_entry!=NULL)
				log_debug("channel %d inserted into open_channels", test_entry->channel_id);
			else
				log_debug("failed insert!");
			return 0;
		}
	}
	return -1;
}

int get_channel_id(uint32_t *channel_id, struct open_channel_entry* channel)
{
	log_debug("in get_channel_id");
	if (channel != NULL){
		*channel_id = channel->channel_id;
		log_debug("found channel with channel_id = %u", *channel_id);
		return 0;
	}else{
		log_debug("no channel found with channel_id = %u", *channel_id);
		return -1;
	}
}

void set_channel_flags(struct tlv_handler_ctx *ctx, struct open_channel_entry* channel)
{
	/*
	 * if no channel flags are sent, we need to use 0, but if no
	 * channel flags are present in the tlv, tlv_packet_get_u32
	 * returns -1
	 */

	if (-1 == tlv_packet_get_u32(ctx->req, TLV_TYPE_FLAGS, &channel->flags))
		channel->flags = 0;
	log_debug("channel flags=%u", channel->flags);

}

char* set_channel_type(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel)
{
	struct mettle *m = ctx->arg;
	log_debug("setting channel type");
	char *str_type = tlv_packet_get_str(ctx->req, TLV_TYPE_CHANNEL_TYPE);
	char *new_str = NULL;
	if (str_type == NULL){
		log_debug("no type found");
	}else{
		uint32_t str_len = strlen(str_type)+1;
		new_str = calloc(1, sizeof(str_len));
		if (new_str != NULL)
			strncpy(new_str, str_type, str_len);
	}
	channel->str_type = new_str;
	channel->handlers = get_channel_handlers(m, new_str);
	if (channel->handlers == NULL)
		log_debug("no handlers found for type %s", new_str);

	return new_str;
}

struct open_channel_entry* core_channel_new(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	log_debug("creating new channel");
	/*
	 * create the entry
	 * do we want to verify we have registered handlers for the channel
	 * before we create it?  Not doing that now, but might be a good idea
	 * this function attempts to run an initialization handler.
	 */
	struct open_channel_entry *channel  = calloc(1, sizeof(struct open_channel_entry));
	if (channel == NULL){
		log_debug("calloc failed");
		return NULL;
	}
	/*
	 * populate the channel_entry data
	 */
	set_channel_flags(ctx, channel);
	if (set_channel_type(ctx, channel) == NULL){
		free(channel);
		return NULL;
	}
	channel->channel_id = 0;
	channel->state = CHANNEL_CLOSED;
	channel->data = NULL;
	/*
	 * register the channel in the open_channels hash table
	 */
	if (-1 == add_channel(m, channel)){
		/*
		 * failed to register channel; give up
		 */
		free(channel);
		return NULL;
	}
	/*
	 * call specific handler for completion
	 * if it exists
	 */
	channel_type_initialize(ctx, channel);
	return channel;
}

int channel_type_initialize(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel)
{
	struct channel_handlers* handler_functions = channel->handlers;
	if (handler_functions != NULL){
		log_debug("specific initializer found");
		return handler_functions->initialize(ctx, channel);
	}
	log_debug("no specific initializer found");
	return -1;
}

struct tlv_packet* channel_type_read(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel)
{
	struct channel_handlers* handler_functions = channel->handlers;
	if (handler_functions != NULL){
		log_debug("specific read found");
		return handler_functions->read(ctx, channel);
	}
	log_debug("no specific read found");
	return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
}

struct tlv_packet* channel_type_write(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel)
{
	struct channel_handlers* handler_functions = channel->handlers;
	if (handler_functions != NULL){
		log_debug("specific write found");
		return handler_functions->write(ctx, channel);
	}
	log_debug("no specific write found");
	return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
}


struct open_channel_entry* get_open_channel(struct tlv_handler_ctx *ctx, uint32_t channel_id)
{
	struct mettle *m = ctx->arg;
	log_debug("mettle location = %p", m);
	struct open_channel_entry **channel_table = mettle_get_channel_instances(m);
	log_debug("channel_table location = %p", *channel_table);
	struct open_channel_entry *channel_entry;
	log_debug("here");
	HASH_FIND_INT(*channel_table, &channel_id, channel_entry);
	return channel_entry;
}

struct tlv_packet *request_general_channel_open(struct tlv_handler_ctx *ctx)
{
	//struct channel_entry *channel=new_channel(ctx);
	log_debug("here");
	const char *extension = tlv_packet_get_str(ctx->req, TLV_TYPE_STRING);
	if (extension == NULL) {
		return NULL;
	}
	return tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
}

int remove_channel(struct tlv_handler_ctx *ctx, struct open_channel_entry* channel)
{
	//free the calloc'd data, too!
	struct mettle *m = ctx->arg;
	struct open_channel_entry **channel_table = mettle_get_channel_instances(m);
	struct open_channel_entry *delete_channel;
	HASH_FIND_INT(*channel_table, &channel->channel_id, delete_channel);
	if (delete_channel == NULL){
		log_debug("no channel with channel_id %d found", channel->channel_id);
		return -1;
	}
	HASH_DEL(*channel_table, channel);
	free(channel);
	log_debug("channel deleted");
	return 0;
}


