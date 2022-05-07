/*
 * lws-minimal-ws-client
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a ws client that connects by default to libwebsockets.org
 * dumb increment ws server.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
/*
 * This represents your object that "contains" the client connection and has
 * the client connection bound to it
 */

static struct my_conn {
    lws_sorted_usec_list_t    sul;         /* schedule connection retry */
    struct lws        *wsi;         /* related wsi if any */
    uint16_t        retry_count; /* count of consequetive retries */
} mco;

static struct lws_context *context;
static int interrupted, port = 443, ssl_connection = LCCSCF_USE_SSL;
static const char *server_address = "libwebsockets.org",
          *pro = "dumb-increment-protocol";

/*
 * The retry and backoff policy we want to use for our client connections
 */

static const uint32_t backoff_ms[] = { 1000, 2000, 3000, 4000, 5000 };

static const lws_retry_bo_t retry = {
    .retry_ms_table            = backoff_ms,
    .retry_ms_table_count        = LWS_ARRAY_SIZE(backoff_ms),
    .conceal_count            = LWS_ARRAY_SIZE(backoff_ms),

    .secs_since_valid_ping        = 3,  /* force PINGs after secs idle */
    .secs_since_valid_hangup    = 10, /* hangup after secs idle */

    .jitter_percent            = 20,
};


#define MAX_PAYLOAD_SIZE  10 * 1024

/**
 * 会话上下文对象，结构根据需要自定义
 */
struct session_data {
    int msg_count;
    unsigned char buf[LWS_PRE + MAX_PAYLOAD_SIZE];
    int len;
};
 
/**
 * 某个协议下的连接发生事件时，执行的回调函数
 *
 * wsi：指向WebSocket实例的指针
 * reason：导致回调的事件
 * user 库为每个WebSocket会话分配的内存空间
 * in 某些事件使用此参数，作为传入数据的指针
 * len 某些事件使用此参数，说明传入数据的长度
 */
int callback( struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len ) {
    struct session_data *data = (struct session_data *) user;
    switch ( reason ) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:   // 连接到服务器后的回调
            lwsl_notice( "Connected to server ok!\n" );
            break;
 
        case LWS_CALLBACK_CLIENT_RECEIVE:       // 接收到服务器数据后的回调，数据为in，其长度为len
            lwsl_notice( "Rx: %s\n", (char *) in );
            break;
        case LWS_CALLBACK_CLIENT_WRITEABLE:     // 当此客户端可以发送数据时的回调
            if ( data->msg_count < 3 ) {
                // 前面LWS_PRE个字节必须留给LWS
                memset( data->buf, 0, sizeof( data->buf ));
                char *msg = (char *) &data->buf[ LWS_PRE ];
                data->len = sprintf( msg, "你好 %d", ++data->msg_count );
                lwsl_notice( "Tx: %s\n", msg );
                // 通过WebSocket发送文本消息
                lws_write( wsi, &data->buf[ LWS_PRE ], (size_t)data->len, LWS_WRITE_TEXT );
            }
            break;
        default:
            break;
    }
    return 0;
}
 
static int
callback_minimal(struct lws *wsi, enum lws_callback_reasons reason,
                 void *user, void *in, size_t len);
/**
 * 支持的WebSocket子协议数组
 * 子协议即JavaScript客户端WebSocket(url, protocols)第2参数数组的元素
 * 你需要为每种协议提供回调函数
 */
struct lws_protocols protocols[] = {
    {
        //协议名称，协议回调，接收缓冲区大小
        "ws", callback_minimal, sizeof( struct session_data ), MAX_PAYLOAD_SIZE, 0, NULL, 0
    },
    {
        NULL, NULL,   0 ,0,0, NULL, 0
    }
};


/*
 * Scheduled sul callback that starts the connection attempt
 */

static void
connect_client(lws_sorted_usec_list_t *sul)
{
    struct my_conn *m = lws_container_of(sul, struct my_conn, sul);


    char address[] = "127.0.0.1";
    int port = 9000;
    char addr_port[256] = { 0 };
    sprintf(addr_port, "%s:%u", address, port & 65535 );
 
    // 客户端连接参数
    struct lws_client_connect_info i = { 0 };
    i.context = context;
    i.address = address;
    i.port = port;
    i.ssl_connection = ssl_connection;
    i.path = "./";
    i.host = addr_port;
    i.origin = addr_port;
    i.protocol = protocols[ 0 ].name;
 

    if (!lws_client_connect_via_info(&i))
        /*
         * Failed... schedule a retry... we can't use the _retry_wsi()
         * convenience wrapper api here because no valid wsi at this
         * point.
         */
        if (lws_retry_sul_schedule(context, 0, sul, &retry,
                       connect_client, &m->retry_count)) {
            lwsl_err("%s: connection attempts exhausted\n", __func__);
            interrupted = 1;
        }
}
#if 1
static int
callback_minimal(struct lws *wsi, enum lws_callback_reasons reason,
         void *user, void *in, size_t len)
{
    printf("callback_minimal---::%d\n",reason);

    struct my_conn *m = (struct my_conn *)user;

    switch (reason) {

    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
             in ? (char *)in : "(null)");
        goto do_retry;
        break;

    case LWS_CALLBACK_CLIENT_RECEIVE:
        lwsl_hexdump_notice(in, len);
        break;

    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        lwsl_user("%s: established\n", __func__);
        break;

    case LWS_CALLBACK_CLIENT_CLOSED:
        goto do_retry;

    default:
        break;
    }

    return lws_callback_http_dummy(wsi, reason, user, in, len);

do_retry:
    /*
     * retry the connection to keep it nailed up
     *
     * For this example, we try to conceal any problem for one set of
     * backoff retries and then exit the app.
     *
     * If you set retry.conceal_count to be larger than the number of
     * elements in the backoff table, it will never give up and keep
     * retrying at the last backoff delay plus the random jitter amount.
     */
    if (lws_retry_sul_schedule_retry_wsi(wsi, &m->sul, connect_client,
                         &m->retry_count)) {
        lwsl_err("%s: connection attempts exhausted\n", __func__);
        interrupted = 1;
    }

    return 0;
}
#endif
//static const struct lws_protocols protocols[] = {
//    { "lws-minimal-client", callback_minimal, 0, 0, 0, NULL, 0 },
//    LWS_PROTOCOL_LIST_TERM
//};


static void
sigint_handler(int sig)
{
    interrupted = 1;
}

int main(int argc, const char **argv)
{
    struct lws_context_creation_info info;
    const char *p;
    int n = 0;

    signal(SIGINT, sigint_handler);
    memset(&info, 0, sizeof info);
    lws_cmdline_option_handle_builtin(argc, argv, &info);

    lwsl_user("LWS minimal ws client\n");

    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.port = CONTEXT_PORT_NO_LISTEN; /* we do not run any server */
    info.protocols = protocols;
    info.iface = NULL;
#define USE_WOLFSSL
#if defined(LWS_WITH_MBEDTLS) || defined(USE_WOLFSSL)
    /*
     * OpenSSL uses the system trust store.  mbedTLS has to be told which
     * CA to trust explicitly.
     */
    //info.client_ssl_ca_filepath = "/Users/lee/Downloads/libwebsockets-main/minimal-examples-lowlevel/ws-client/minimal-ws-client/libwebsockets.org.cer";
    //info.client_ssl_ca_filepath = "/Users/lee/Desktop/TEST/websocket/libwebsockets/all-platform/libwebsockets/certs/client-key.pem";
   // info.client_ssl_ca_filepath = "/Users/lee/Desktop/TEST/websocket/libwebsockets/all-platform/libwebsockets/certs/client-cert.pem";

    
    info.ssl_cert_filepath = "/Users/lee/Desktop/TEST/websocket/libwebsockets/all-platform/libwebsockets/certs/client-cert.pem";
    info.ssl_private_key_filepath = "/Users/lee/Desktop/TEST/websocket/libwebsockets/all-platform/libwebsockets/certs/client-key.pem";
    info.ssl_ca_filepath ="/Users/lee/Desktop/TEST/websocket/libwebsockets/all-platform/libwebsockets/certs/ca.pem";
    
#endif

    if ((p = lws_cmdline_option(argc, argv, "--protocol")))
        pro = p;

    if ((p = lws_cmdline_option(argc, argv, "-s")))
        server_address = p;

    if ((p = lws_cmdline_option(argc, argv, "-p")))
        port = atoi(p);

    if (lws_cmdline_option(argc, argv, "-n"))
        ssl_connection &= ~LCCSCF_USE_SSL;

    if (lws_cmdline_option(argc, argv, "-j"))
        ssl_connection |= LCCSCF_ALLOW_SELFSIGNED;

    if (lws_cmdline_option(argc, argv, "-k"))
        ssl_connection |= LCCSCF_ALLOW_INSECURE;

    if (lws_cmdline_option(argc, argv, "-m"))
        ssl_connection |= LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;

    if (lws_cmdline_option(argc, argv, "-e"))
        ssl_connection |= LCCSCF_ALLOW_EXPIRED;

    info.fd_limit_per_thread = 1 + 1 + 1;

    context = lws_create_context(&info);
    if (!context) {
        lwsl_err("lws init failed\n");
        return 1;
    }

    /* schedule the first client connection attempt to happen immediately */
    lws_sul_schedule(context, 0, &mco.sul, connect_client, 1);

    while (n >= 0 && !interrupted)
        n = lws_service(context, 0);

    lws_context_destroy(context);
    lwsl_user("Completed\n");

    return 0;
}
