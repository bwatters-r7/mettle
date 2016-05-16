#include <uv.h>

#include "mettle.h"
#include "tlv.h"
#include "uthash.h"

#define CHANNEL_OPEN 1
#define CHANNEL_CLOSED 0

struct open_channel_entry;
typedef struct tlv_packet * (*channel_handler)(struct tlv_handler_ctx *ctx, struct open_channel_entry* channel);
typedef int (*channel_initializer)(struct tlv_handler_ctx *ctx, struct open_channel_entry* channel);

struct channel_handlers{
	channel_initializer initialize;
	channel_handler 	read;
	channel_handler 	write;
	channel_handler 	interact;
	channel_handler 	close;
};

struct channel_type_entry{
	char* 						str_type;
	struct channel_handlers*	handlers;
	UT_hash_handle 				hh;
};

struct open_channel_entry{
	uint32_t 					channel_id;
	void*						data;
	uint32_t 					flags;
	struct channel_type_entry*	type;
	UT_hash_handle 				hh;
	char* 						path;
	char						state;
	char*	 					str_type;
	uv_file 					uv_fd;
};

extern int fs_file_initialize(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel);
extern struct tlv_packet * fs_file_interact(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel);
extern struct tlv_packet * fs_file_close(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel);
extern struct tlv_packet * fs_file_read(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel);
extern struct tlv_packet * fs_file_write(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel);

int add_channel(struct mettle *m, struct open_channel_entry* channel);
int tlv_register_default_channel_dispatchers(struct mettle *m);
struct channel_type_entry* tlv_register_channel_handlers(struct mettle *m,
		char* str_type,
		channel_initializer channel_initialize,
		channel_handler channel_read,
		channel_handler channel_write,
		channel_handler channel_interact,
		channel_handler channel_close);
uint32_t get_int_channel_type(struct mettle *m, const char* str_type);
struct open_channel_entry* get_open_channel(struct tlv_handler_ctx *ctx, uint32_t channel_id);
int get_channel_id(uint32_t *channel_id, struct open_channel_entry* channel);
channel_handler get_handler(char *request_type);
struct open_channel_entry* core_channel_new(struct tlv_handler_ctx *ctx);
int remove_channel(struct tlv_handler_ctx *ctx, struct open_channel_entry* channel);
//struct tlv_packet *request_general_channel_open(struct tlv_handler_ctx *ctx);
struct tlv_packet *request_fs_file_channel_open(struct tlv_handler_ctx *ctx);
struct channel_dispatcher_entry* get_dispatch_data(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel);
int channel_type_initialize(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel);
struct tlv_packet* channel_type_read(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel);
struct tlv_packet* channel_type_write(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel);
struct channel_handlers* get_channel_handlers(struct mettle *m, const char* str_type);
struct channel_type_entry* get_channel_type_entry(struct mettle *m, const char* str_type);
void set_channel_flags(struct tlv_handler_ctx *ctx, struct open_channel_entry* channel);
char* set_channel_type(struct tlv_handler_ctx *ctx, struct open_channel_entry *channel);
