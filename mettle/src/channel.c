#include <limits.h>

#include "channel.h"
#include "log.h"
#include "uthash.h"

/*
 * adds the channel to the open channel hash table held by mettle
 * so it can be referenced by the channel_id
 * on success, returns 0
 * on error, returns -1
 */
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

/*
 * this is the constructor for the channel "class"
 * it creates the struct in memory and populates:
 * -channel type and str_type via set_channel_type()
 * -channel flags via set_channel_flags
 * -channel state (closed)
 * -channel data (NULL)
 *
 * provided for the specified type
 * attempts to register the channel in the open channel
 * table
 */
struct open_channel_entry* core_channel_new(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	log_debug("creating new channel");
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

/*
 * gives access to the channel_handlers entry in the handlers table
 * for a given string type
 * on error, returns NULL
 */
struct channel_handlers* get_channel_handlers(struct mettle *m, const char* str_type)
{
	log_debug("in get_channel_handlers");
	log_debug("looking for %s", str_type);
	struct channel_type_entry *type_entry = get_channel_type_entry(m, str_type);
	if (type_entry == NULL)
		return NULL;
	return type_entry->handlers;
}

/*
 * gets the channel id for a given channel open_channel struct
 * on success, returns 0
 * on error, returns -1
 */
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

/*
 * returns the type entry from the channel type table for a given channel type
 * on error, returns NULL
 */
struct channel_type_entry* get_channel_type_entry(struct mettle *m, const char* str_type)
{
	log_debug("in get_channel_handlers");
	log_debug("looking for %s", str_type);
	struct channel_type_entry **type_table = mettle_get_channel_type_table(m);
	struct channel_type_entry *type_entry;
	HASH_FIND_STR(*type_table, str_type, type_entry);
	if (type_entry != NULL)
		return type_entry;
	return NULL;
}

/*
 * wrapper function that calls the corresponding registered
 * close function for a given channel
 */
struct tlv_packet* channel_type_close(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel)
{
	struct channel_handlers* handler_functions = channel->type->handlers;
	if (handler_functions != NULL){
		log_debug("specific close found");
		return handler_functions->close(ctx, channel);
	}
	log_debug("no specific close found");
	return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
}

/*
 * wrapper function that calls the corresponding registered
 * initialization function for a given channel
 */
int channel_type_initialize(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel)
{
	struct channel_handlers* handler_functions = channel->type->handlers;
	if (handler_functions != NULL){
		log_debug("specific initializer found");
		return handler_functions->initialize(ctx, channel);
	}
	log_debug("no specific initializer found");
	return -1;
}

/*
 * wrapper function that calls the corresponding registered
 * interact function for a given channel
 */
struct tlv_packet* channel_type_interact(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel)
{
	struct channel_handlers* handler_functions = channel->type->handlers;
	if (handler_functions != NULL){
		log_debug("specific interact found");
		return handler_functions->interact(ctx, channel);
	}
	log_debug("no specific interact found");
	return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
}

/*
 * wrapper function that calls the corresponding registered
 * read function for a given channel
 */
struct tlv_packet* channel_type_read(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel)
{
	struct channel_handlers* handler_functions = channel->type->handlers;
	if (handler_functions != NULL){
		log_debug("specific read found");
		return handler_functions->read(ctx, channel);
	}
	log_debug("no specific read found");
	return tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
}

/*
 * wrapper function that calls the corresponding registered
 * write function for a given channel
 */
struct tlv_packet* channel_type_write(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel)
{
	struct channel_handlers* handler_functions = channel->type->handlers;
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

/*
 * registers a core_chanel type with its default handlers
 * if the type is already registered, the handlers are updated
 * because all types get the dispatch handlers from this table
 * updating the entry will update the handlers for all channels
 * of the specified type, both past and future
 */
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
	struct channel_handlers *handler_entry = calloc(1, sizeof(struct channel_handlers));
	if (handler_entry == NULL)
	{
		return NULL;
	}
	handler_entry->initialize = channel_initialize;
	handler_entry->read = channel_read;
	handler_entry->write = channel_write;
	handler_entry->interact = channel_interact;
	handler_entry->close = channel_close;
	/*
	 * try to find it in the type table
	 */
	type_entry = get_channel_type_entry(m, str_type);
	if (type_entry != NULL){
		/*
		 * it is already there; free the old handler struct
		 * and update the pointer to the new handers
		 */
		if (type_entry->handlers != NULL)
			free(type_entry->handlers);
		type_entry->handlers = handler_entry;
	}else{
		/*
		 * the type entry is not there, so we have to create
		 * everything and populate it.
		 */
		uint32_t str_len = strlen(str_type)+1;
		char* new_str = calloc(1, str_len);
		type_entry = calloc(1, sizeof(struct channel_type_entry));
		strncpy(new_str, str_type, str_len);
		/*
		 * are all our structs valid?
		 */
		if ((new_str == NULL) || (type_entry == NULL)){
			return NULL;
		}
		type_entry->handlers=handler_entry;
		type_entry->str_type = new_str;
		HASH_ADD_KEYPTR(hh, *type_table, type_entry->str_type, strlen(type_entry->str_type), type_entry);
	}
	return type_entry;
}


/*
 * registers the default dispatch routines for a given
 * type of function in the channel type table.
 * if you want to make sure a type and its handlers are
 * registered at startup, place them here
 */
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

/*
 * sets the channel flags in a given open channel object
 */
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

/*
 * sets two entries in the open channel entry:
 * it always sets the string type value in the open channel
 * to match the new name
 * it sets the channel type entry to point to the proper entry
 * in the type table so the correct dispacher methods are called
 * if the type has been registered using the
 * tlv_register_channel_handlers function
 * if the type has not been registered, it sets the type entry
 * pointer to NULL, and dispatches will fail.
 *
 * for the dispatcher to work properly, you must call
 * this function only after registering the type.
 */
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
	channel->type = get_channel_type_entry(m, new_str);
	if (channel->type == NULL)
		log_debug("no handlers found for type %s", new_str);
	return new_str;
}
