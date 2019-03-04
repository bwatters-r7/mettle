#ifndef _METTLE_PINGBACK_H_
#define _METTLE_PINGBACK_H_

#include "mettle.h"
#include "bufferev.h"

struct mettle_pingback;

struct pingback_object;

void mettle_pingback_free(struct mettle_pingback *mpingback);

struct mettle_pingback * mettle_pingback_new(struct mettle *m, const char *addr, uint16_t port);

typedef void (*pingback_read_cb)(struct pingback_object *obj, void *arg);

#endif
