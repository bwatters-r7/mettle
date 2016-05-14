/**
 * Copyright 2015 Rapid7
 * @brief mettle main object
 * @file mettle.h
 */

#ifndef _METTLE_H_
#define _METTLE_H_

#include <sigar.h>
#include <uv.h>

struct mettle * mettle(void);

int mettle_start(struct mettle *m);

const char *mettle_get_fqdn(struct mettle *m);

sigar_t *mettle_get_sigar(struct mettle *m);

uv_loop_t * mettle_get_loop(struct mettle *m);

struct tlv_dispatcher *mettle_get_tlv_dispatcher(struct mettle *m);

void mettle_free(struct mettle *);

int mettle_add_server_uri(struct mettle *m, const char *uri);

int mettle_add_tcp_sock(struct mettle *m, int fd);

struct channel_map_entry *mettle_get_channel_types(struct mettle *m);

struct open_channel_entry **mettle_get_channel_instances(struct mettle *m);

struct channel_dispatcher_entry *mettle_get_channel_dispatcher(struct mettle *m);

#endif
