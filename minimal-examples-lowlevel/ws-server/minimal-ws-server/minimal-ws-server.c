/*
 * lws-minimal-ws-server
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates the most minimal http server you can make with lws,
 * with an added websocket chat server.
 *
 * To keep it simple, it serves stuff in the subdirectory "./mount-origin" of
 * the directory it was started in.
 * You can change that by changing mount.origin.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#define LWS_PLUGIN_STATIC
#include "protocol_lws_minimal.c"

//static struct lws_protocols protocols[] = {
//	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0},
//	LWS_PLUGIN_PROTOCOL_MINIMAL,
//	LWS_PROTOCOL_LIST_TERM
//};


#define MAX_PAYLOAD_SIZE  10 * 1024

/**
 * 会话上下文对象，结构根据需要自定义
 */
struct session_data {
    int msg_count;
    unsigned char buf[LWS_PRE + MAX_PAYLOAD_SIZE];
    int len;
    bool bin;
    bool fin;
};

static int protocol_my_callback( struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len ) {
    struct session_data *data = (struct session_data *) user;
    printf("protocol_my_callback---::%d\n",reason);
    switch ( reason ) {
        case LWS_CALLBACK_ESTABLISHED:       // 当服务器和客户端完成握手后
            printf("Client connect!\n");
            break;
        case LWS_CALLBACK_RECEIVE:           // 当接收到客户端发来的帧以后
            // 判断是否最后一帧
            data->fin = lws_is_final_fragment( wsi );
            // 判断是否二进制消息
            data->bin = lws_frame_is_binary( wsi );
            // 对服务器的接收端进行流量控制，如果来不及处理，可以控制之
            // 下面的调用禁止在此连接上接收数据
            lws_rx_flow_control( wsi, 0 );
 
            // 业务处理部分，为了实现Echo服务器，把客户端数据保存起来
            memcpy( &data->buf[ LWS_PRE ], in, len );
            data->len = (int)len;
            printf("recvied message:%s\n",(char*)in);
 
            // 需要给客户端应答时，触发一次写回调
            lws_callback_on_writable( wsi );
            break;
        case LWS_CALLBACK_SERVER_WRITEABLE:   // 当此连接可写时
            lws_write( wsi, &data->buf[ LWS_PRE ], (size_t)(data->len), LWS_WRITE_TEXT );
            // 下面的调用允许在此连接上接收数据
            lws_rx_flow_control( wsi, 1 );
            break;
        default:
            break;
    }
    // 回调函数最终要返回0，否则无法创建服务器
    return 0;
}

/**
 * 支持的WebSocket子协议数组
 * 子协议即JavaScript客户端WebSocket(url, protocols)第2参数数组的元素
 * 你需要为每种协议提供回调函数
 */
struct lws_protocols protocols[] = {
    {
        //协议名称，协议回调，接收缓冲区大小
        "ws", protocol_my_callback, sizeof( struct session_data ), MAX_PAYLOAD_SIZE, 0, NULL, 0
    },
    {
        NULL, NULL,   0 ,0,0, NULL, 0
    }
};
 


static const lws_retry_bo_t retry = {
	.secs_since_valid_ping = 3,
	.secs_since_valid_hangup = 10,
};

static int interrupted;
#if 0
static const struct lws_http_mount mount = {
	/* .mount_next */		NULL,		/* linked-list "next" */
	/* .mountpoint */		"/",		/* mountpoint URL */
	/* .origin */			"./mount-origin",  /* serve from dir */
	/* .def */			"index.html",	/* default filename */
	/* .protocol */			NULL,
	/* .cgienv */			NULL,
	/* .extra_mimetypes */		NULL,
	/* .interpret */		NULL,
	/* .cgi_timeout */		0,
	/* .cache_max_age */		0,
	/* .auth_mask */		0,
	/* .cache_reusable */		0,
	/* .cache_revalidate */		0,
	/* .cache_intermediaries */	0,
	/* .cache_no */			0,
	/* .origin_protocol */		LWSMPRO_FILE,	/* files in a dir */
	/* .mountpoint_len */		1,		/* char count */
	/* .basic_auth_login_file */	NULL,
};
#endif

#if defined(LWS_WITH_PLUGINS)
/* if plugins enabled, only protocols explicitly named in pvo bind to vhost */
static struct lws_protocol_vhost_options pvo = { NULL, NULL, "lws-minimal", "" };
#endif

void sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS minimal ws server | visit http://localhost:7681 (-s = use TLS / https)\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
    //char address[] = "127.0.0.1";
    info.port = 9000;
    info.iface = NULL; // 在所有网络接口上监听
    info.protocols = protocols;
    info.gid = (gid_t)-1;
    info.uid = (gid_t)-1;
    info.options = LWS_SERVER_OPTION_VALIDATE_UTF8;

#if defined(LWS_WITH_PLUGINS)
	info.pvo = &pvo;
#endif
	info.options =
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

#if defined(LWS_WITH_TLS)
	if (lws_cmdline_option(argc, argv, "-s")) {
		lwsl_user("Server using TLS\n");
		info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
//		info.ssl_cert_filepath = "/Users/lee/Downloads/libwebsockets-main/minimal-examples-lowlevel/ws-server/minimal-ws-server/localhost-100y.cert";
//		info.ssl_private_key_filepath = "/Users/lee/Downloads/libwebsockets-main/minimal-examples-lowlevel/ws-server/minimal-ws-server/localhost-100y.key";
   //     info.ssl_cert_filepath = "/Users/lee/Desktop/Develop/apache-tomcat-9.0.62/key/.keystore";
        info.ssl_cert_filepath = " /Users/lee/Desktop/TEST/websocket/libwebsockets/all-platform/libwebsockets/certs/server-cert.pem";
        info.ssl_private_key_filepath = " /Users/lee/Desktop/TEST/websocket/libwebsockets/all-platform/libwebsockets/certs/server-key.pem";
        info.ssl_ca_filepath =" /Users/lee/Desktop/TEST/websocket/libwebsockets/all-platform/libwebsockets/certs/ca.pem";
	}
#endif

	if (lws_cmdline_option(argc, argv, "-h"))
		info.options |= LWS_SERVER_OPTION_VHOST_UPG_STRICT_HOST_CHECK;

	if (lws_cmdline_option(argc, argv, "-v"))
		info.retry_and_idle_policy = &retry;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	return 0;
}
