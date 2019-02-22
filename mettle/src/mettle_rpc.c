#include <string.h>

#include "json.h"
#include "log.h"
#include "mettle_rpc.h"
#include "network_server.h"
#include "utlist.h"

struct mettle_rpc {
	struct mettle *m;
	int running;
	struct network_server *ns;
	struct json_rpc *jrpc;
	struct mettle_rpc_conn {
		struct mettle_rpc *mrpc;
		struct json_tokener *tok;
		struct bufferev *bev;
		struct mettle_rpc_conn *next;
	} *conns;
};

static struct mettle_rpc_conn * get_conn(struct mettle_rpc *mrpc,
	struct bufferev *bev)
{
  log_info("get_conn");
	struct mettle_rpc_conn *conn;
	LL_FOREACH(mrpc->conns, conn) {
		if (conn->bev == bev) {
			return conn;
		}
	}

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		return NULL;
	}

	conn->mrpc = mrpc;
	conn->bev = bev;
	conn->tok = json_tokener_new();
	if (!conn->tok) {
		free(conn);
		return NULL;
	}

	LL_APPEND(mrpc->conns, conn);
	return conn;
}

static void handle_rpc(struct json_object *obj, void *arg)
{
  log_info("handle_rpc");

	struct mettle_rpc_conn *conn = arg;

	struct json_object *response = NULL;
	if (obj != NULL) {
		response = json_rpc_process(conn->mrpc->jrpc, obj);
	} else {
		enum json_tokener_error rc = json_tokener_get_error(conn->tok);
		if (rc != json_tokener_continue) {
			response = json_rpc_gen_error(conn->mrpc->jrpc,
				NULL, JSON_RPC_PARSE_ERROR, "Parse error");
			json_tokener_reset(conn->tok);
		}
	}
	if (response) {
		const char *str = json_object_to_json_string_ext(response, 0);
		bufferev_write(conn->bev, str, strlen(str));
		json_object_put(response);
	}
	json_object_put(obj);
}

static void read_cb(struct bufferev *bev, void *arg)
{
  log_info("read_cb");
	struct mettle_rpc *mrpc = arg;
	struct mettle_rpc_conn *conn = get_conn(mrpc, bev);
	if (conn) {
		json_read_bufferev_cb(bev, conn->tok, handle_rpc, conn);
	} else {
		bufferev_free(bev);
	}
}

static void event_cb(struct bufferev *bev, int event, void *arg)
{
  log_info("event_cb");
	struct mettle_rpc *mrpc = arg;

	log_info("got connect");
	if (event & (BEV_EOF|BEV_ERROR)) {
		struct mettle_rpc_conn *conn = get_conn(mrpc, bev);
		if (conn) {
			LL_DELETE(mrpc->conns, conn);
			json_tokener_free(conn->tok);
			free(conn);
		}
	}
}

void mettle_rpc_free(struct mettle_rpc *mrpc)
{
  log_info("json_read_bufferev_cb");
	if (mrpc) {
		if (mrpc->jrpc) {
			json_rpc_free(mrpc->jrpc);
		}
		if (mrpc->ns) {
			network_server_free(mrpc->ns);
		}
		free(mrpc);
	}
}

static json_object *handle_message(struct json_method_ctx *json_ctx, void *arg)
{
    log_info("handle_message");
    struct mettle *m = arg;
    const char *message, *level;
    json_get_str(json_ctx->params, "message", &message);
    json_get_str_def(json_ctx->params, "level", &level, "debug");
    if (strcmp(level, "error") == 0) {
        log_error("[%s] %s", level, message);
    } else {
        log_info("[%s] %s", level, message);
    }
    return NULL;
}


struct mettle_rpc * mettle_rpc_new(struct mettle *m, const char *addr, uint16_t port)
{
  log_info("mettle_rpc_new");
	struct mettle_rpc *mrpc = calloc(1, sizeof(*mrpc));
	if (mrpc == NULL) {
		return NULL;
	}

	mrpc->m = m;

	mrpc->jrpc = json_rpc_new(JSON_RPC_CHECK_VERSION);
	if (mrpc->jrpc == NULL) {
		goto err;
	}

	json_rpc_register_method(mrpc->jrpc, "message", "message,level", handle_message, m);

	mrpc->ns = network_server_new(mettle_get_loop(m));
	if (network_server_listen_tcp(mrpc->ns, addr, port) == -1) {
		log_info("failed to listen on %s:%d", addr, port);
		goto err;
	}

	network_server_setcbs(mrpc->ns, read_cb, NULL, event_cb, mrpc);

	return mrpc;

err:
	mettle_rpc_free(mrpc);
	return NULL;
}
