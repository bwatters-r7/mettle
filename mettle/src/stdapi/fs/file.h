#include "../../channel.h"

int fs_file_initialize(struct tlv_handler_ctx *ctx, struct channel_entry *channel);
int fs_file_interact(struct tlv_handler_ctx *ctx, struct channel_entry *channel);
int fs_file_close(struct tlv_handler_ctx *ctx, struct channel_entry *channel);
int fs_file_read(struct tlv_handler_ctx *ctx, struct channel_entry *channel);
int fs_file_write(struct tlv_handler_ctx *ctx, struct channel_entry *channel);
