#include <limits.h>

#include "channel.h"
#include "log.h"
#include "uthash.h"

/*
 * the defines here go with the channel_table structure;
 * hopefully, we will move away form a string type in the
 * tlv_packet, so this bridges the gap as it were.
 * when framework implements numeric type codes, this will
 * require minimal changes.
 *
 * if you add another STDAPI type, it must be #defined and
 * entered into the dispatch table.
 */
#define STDAPI_FS_FILE 			1
#define STDAPI_NET_TCP_CLIENT 	2
#define STDAPI_NET_TCP_SERVER 	3
#define STDAPI_NET_UDP_CLIENT	4

/*
 * the following struct pointers are entry points for UT hash objects.
 * registered_types
 * contains a mapping of string types used by framework to numeric
 * types used by mettle.
 * populated/queried by get_numeric_channel_type
 * queried by get_str_channel_type
 * depopulated by delete_channel_type
 *
 * dispatch_table
 * contains a mapping of numeric channel types to handler functions
 * populated by register_channel_type
 * depopulated by deregister_channel_type
 *
 * open_channels
 * contains the currently open channels
 * populated by add_chanel
 * depopulated by remove_channel
 *
 */

/* either send back the numeric type value associated with a string value
 * or register it and send the new value back.
 */

int tlv_register_default_channel_dispatchers(struct mettle *m,
		struct channel_dispatcher_entry **dispatch_table)
{
	log_debug("registering stdapi_fs_file_type in mettle object %p", m);
	tlv_register_channel_dispatcher_str(m,
			dispatch_table,
			"stdapi_fs_file_type",
			fs_file_initialize,
			fs_file_read,
			fs_file_write,
			fs_file_interact,
			fs_file_close);
	return 0;
}

int tlv_register_channel_dispatcher_str(struct mettle *m,
		struct channel_dispatcher_entry **dispatch_table,
		char *str_type,
		channel_initializer channel_initialize,
		channel_handler channel_read,
		channel_handler channel_write,
		channel_handler channel_interact,
		channel_handler channel_close)
{
	return tlv_register_channel_dispatcher(m,
			dispatch_table,
			get_int_channel_type(m, str_type),
			channel_initialize,
			channel_read,
			channel_write,
			channel_interact,
			channel_close);
}

int tlv_register_channel_dispatcher(struct mettle *m,
		struct channel_dispatcher_entry **dispatch_table,
		uint32_t int_type,
		channel_initializer channel_initialize,
		channel_handler channel_read,
		channel_handler channel_write,
		channel_handler channel_interact,
		channel_handler channel_close)
{
	/*
	 * this should be relocated to startup, but I'm not sure where that is.
	 */
//	if (channel_dispatch_table == NULL)
//		register_default_dispatch_routines();
	/*
	 * check to see if that type has already been registered
	 */
	struct channel_dispatcher_entry* entry;
	HASH_FIND_INT(*dispatch_table, &int_type, entry);
	if (entry != NULL){
		log_debug("handlers already registered for %u type", int_type);
		return 0;
	}else{
		log_debug("registering dispatchers for %u", int_type);
		entry = calloc(1, sizeof(struct channel_dispatcher_entry));
		entry->initialize=channel_initialize;
		entry->int_type = int_type;
		entry->read = channel_read;
		entry->write = channel_write;
		entry->interact = channel_interact;
		entry->close = channel_close;
		HASH_ADD_INT(*dispatch_table, int_type, entry);
		log_debug("channel %u inserted into open_channels", entry->int_type);
		return 1;
	}
}

uint32_t get_int_channel_type(struct mettle *m, const char* str_type)
{
	struct channel_map_entry *type_table = mettle_get_channel_types(m);
	struct channel_map_entry *type_entry;
	for(type_entry = type_table; type_entry != NULL; type_entry = type_entry->hh.next){
		if (!strcmp(str_type, type_entry->str_type))
			return type_entry->int_type;
	}
	/*
	 * could not find the type; place it in the hash table
	 * create the entry first, then add it.
	 */
	struct channel_map_entry* new_entry = calloc(1, sizeof(struct channel_map_entry));
	uint32_t str_len = strlen(str_type)+1;
	new_entry->str_type = calloc(str_len, sizeof(char));
	strncpy(new_entry->str_type, str_type, str_len);
	for(uint32_t i = 1; i <= INT_MAX; i++){
		HASH_FIND_INT(type_table, &i, type_entry);
		if (type_entry == NULL){
			new_entry->int_type = i;
			HASH_ADD_INT(type_table, int_type, new_entry);
			log_debug("type %d inserted into channel_type_map", new_entry->int_type);
			break;
		}
	}
	return new_entry->int_type;
}

int add_channel(struct mettle *m, struct open_channel_entry* channel_in)
{
	/*
	 * channel_id 0 used by framework for keep-alive messages
	 * this should be changed on the framework side.
	 * until then, we start looking for open spots at 1
	 * rather than 0
	 */
	struct open_channel_entry *channel_table = mettle_get_channel_instances(m);
	log_debug("mettle location = %p", m);
	log_debug("channel_table location = %p", channel_table);
	struct open_channel_entry *channel_entry;
	log_debug("here");
	for(uint32_t i = 1; i <= INT_MAX; i++){
		HASH_FIND_INT(channel_table, &i, channel_entry);
		if (channel_entry == NULL){
			channel_in->channel_id = i;
			HASH_ADD_INT(channel_table, channel_id, channel_in);
			log_debug("channel_table location = %p", channel_table);
			log_debug("channel %d inserted into open_channels", channel_in->channel_id);
			struct open_channel_entry *test_entry;
			HASH_FIND_INT(channel_table, &channel_in->channel_id, test_entry);
			if (test_entry!=NULL)
				log_debug("channel %d inserted into open_channels", test_entry->channel_id);
			else
				log_debug("failed insert!");
			return 0;
		}
	}
	return -1;
}

int get_channel_id(struct open_channel_entry* channel, uint32_t *channel_id)
{
	if (channel != NULL){
		*channel_id = channel->channel_id;
		return 0;
	}else{
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

int set_channel_type(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel)
{
	struct mettle *m = ctx->arg;
	log_debug("setting channel type");
	char *str_type = tlv_packet_get_str(ctx->req, TLV_TYPE_CHANNEL_TYPE);
	if (str_type == NULL){
		log_debug("found type %s", str_type);
		return -1;
	}
	channel->int_type = get_int_channel_type(m, str_type);
	return 0;
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
	if (set_channel_type(ctx, channel) == -1){
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
	channel_dispatch_initialize(ctx, channel);
	return channel;
}

int channel_dispatch_initialize(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel)
{
	struct channel_dispatcher_entry* dispatch_entry = get_dispatch_data(ctx, channel);
	if (dispatch_entry->initialize != NULL){
		log_debug("specific initializer found");
		return dispatch_entry->initialize(ctx, channel);
	}
	log_debug("no specific initializer found");
	return -1;
}

struct tlv_packet* channel_dispatch_read(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel)
{
	struct channel_dispatcher_entry* dispatch_entry = get_dispatch_data(ctx, channel);
	if (dispatch_entry->read != NULL){
		log_debug("specific read found");
		return dispatch_entry->read(ctx, channel);
	}
	log_debug("no specific read found");
	return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
}

struct tlv_packet* channel_dispatch_write(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel)
{
	struct channel_dispatcher_entry* dispatch_entry = get_dispatch_data(ctx, channel);
	if (dispatch_entry->read != NULL){
		log_debug("specific write found");
		return dispatch_entry->write(ctx, channel);
	}
	log_debug("no specific write found");
	return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
}


struct open_channel_entry* get_open_channel(struct tlv_handler_ctx *ctx, uint32_t channel_id)
{
	struct mettle *m = ctx->arg;
	log_debug("mettle location = %p", m);
	struct open_channel_entry *channel_table = mettle_get_channel_instances(m);
	log_debug("channel_table location = %p", channel_table);
	struct open_channel_entry *channel_entry;
	log_debug("here");
	HASH_FIND_INT(channel_table, &channel_id, channel_entry);
	return channel_entry;
}
struct channel_dispatcher_entry* get_dispatch_data(struct tlv_handler_ctx *ctx,
		struct open_channel_entry *channel)
{
	struct mettle *m = ctx->arg;
	struct channel_dispatcher_entry *dispatch_table = mettle_get_channel_dispatcher(m);
	struct channel_dispatcher_entry *dispatcher_entry;
	HASH_FIND_INT(dispatch_table, &channel->int_type, dispatcher_entry);
	return dispatcher_entry;
}

int print_channel_data(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel)
{
	struct channel_dispatcher_entry *dispatcher_entry = get_dispatch_data(ctx, channel);
	log_debug("channel_id=%u", channel->channel_id);
	if (dispatcher_entry->initialize == NULL)
		log_debug("dispatcher_entry->initialize is NULL");
	else
		log_debug("dispatcher_entry->initialize is not NULL");
	if (dispatcher_entry->read == NULL)
		log_debug("dispatcher_entry->read is NULL");
	else
		log_debug("dispatcher_entry->read is not NULL");
	if (dispatcher_entry->write == NULL)
		log_debug("dispatcher_entry->write is NULL");
	else
		log_debug("dispatcher_entry->write is not NULL");
	if (dispatcher_entry->close == NULL)
		log_debug("dispatcher_entry->close is NULL");
	else
		log_debug("dispatcher_entry->close is NULL");
	if (dispatcher_entry->interact == NULL)
		log_debug("dispatcher_entry->interact is NULL");
	else
		log_debug("dispatcher_entry->interact is NULL");

	log_debug("channel->flags=%u", channel->flags);
	log_debug("channel->path=%s", channel->path);
	log_debug("channel->state=%u", channel->state);
	log_debug("channel->int_type=%u", channel->int_type);
	return 0;

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
	struct open_channel_entry *channel_table = mettle_get_channel_instances(m);
	struct open_channel_entry *delete_channel;
	HASH_FIND_INT(channel_table, &channel->channel_id, delete_channel);
	if (delete_channel == NULL){
		log_debug("no channel with channel_id %d found", channel->channel_id);
		return -1;
	}
	HASH_DEL(channel_table, channel);
	free(channel);
	log_debug("channel deleted");
	return 0;
}


