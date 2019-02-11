#ifndef _METTLE_RPC_H_
#define _METTLE_RPC_H_

#include "mettle.h"

struct mettle_rpc;

void mettle_rpc_free(struct mettle_rpc *mrpc);

struct mettle_rpc * mettle_rpc_new(struct mettle *m, const char *addr, uint16_t port);

#endif
