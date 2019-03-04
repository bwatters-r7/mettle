#include <string.h>

#include "bufferev.h"
#include "mettle_pingback.h"
#include "json.h"
#include "log.h"
#include "network_server.h"
#include "utlist.h"

struct mettle_pingback {
	struct mettle *m;
	int running;
	struct network_server *ns;
	struct mettle_pingback_conn {
		struct mettle_pingback *mpingback;
		struct bufferev *bev;
		struct mettle_pingback_conn *next;
	} *conns;
};

struct pingback_object {
	struct mettle *m;
	int running;
	struct network_server *ns;
	struct mettle_pingback_conn *conns;
  char * test_string;
};

static void handle_pingback(struct pingback_object *obj, void *arg)
{
  log_info("handle_pingback");
  log_info("%s\n", obj->test_string);
}

void mettle_pingback_free(struct mettle_pingback *mpingback)
{
  log_info("mettle_pingpback_free");
	if (mpingback) {
		if (mpingback->ns) {
			network_server_free(mpingback->ns);
		}
		free(mpingback);
	}
}

static struct mettle_pingback_conn * get_conn(struct mettle_pingback *mpingback,
	struct bufferev *bev)
{
  log_info("mettle_pingback_conn");
	struct mettle_pingback_conn *conn;
	LL_FOREACH(mpingback->conns, conn) {
		if (conn->bev == bev) {
			return conn;
		}
	}
	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		return NULL;
	}

	conn->mpingback = mpingback;
	conn->bev = bev;

	LL_APPEND(mpingback->conns, conn);
	return conn;
}

void pingback_read_bufferev_cb(struct bufferev *bev, pingback_read_cb cb, void *arg){
  log_info("pingback_read_bufferev_cb");
	char buf[4096];
	size_t buf_len, last_read = 0;
	do {
		buf_len = bufferev_read(bev, buf, sizeof(buf));
		if (buf_len) {
      log_info("%s\n", buf);
    }
	} while (buf_len);
}

static void event_cb(struct bufferev *bev, int event, void *arg)
{
  log_info("event_cb");
	struct mettle_pingback *mpingback = arg;

	log_info("got connect");
	if (event & (BEV_EOF|BEV_ERROR)) {
		struct mettle_pingback_conn *conn = get_conn(mpingback, bev);
		if (conn) {
			LL_DELETE(mpingback->conns, conn);
			free(conn);
		}
	}
}
static void read_cb(struct bufferev *bev, void *arg)
{
  log_info("read_cb");
	struct mettle_pingback *mpingback = arg;
	struct mettle_pingback_conn *conn = get_conn(mpingback, bev);
	if (conn) {
		pingback_read_bufferev_cb(bev, handle_pingback, conn);
	} else {
		bufferev_free(bev);
	}
}

struct mettle_pingback * mettle_pingback_new(struct mettle *m, const char *addr, uint16_t port)
{
  log_info("mettle_pingback_new");
	struct mettle_pingback *mpingback = calloc(1, sizeof(*mpingback));
	if (mpingback == NULL) {
		return NULL;
	}

	mpingback->m = m;

	mpingback->ns = network_server_new(mettle_get_loop(m));
	if (network_server_listen_tcp(mpingback->ns, addr, port) == -1) {
		log_info("failed to listen on %s:%d", addr, port);
		goto err;
	}

	network_server_setcbs(mpingback->ns, read_cb, NULL, event_cb, mpingback);

	return mpingback;

err:
	mettle_pingback_free(mpingback);
	return NULL;
}
