
/*
 * Copyright (C) Cloudflare, Inc.
 */


#ifndef _NGX_EVENT_QUIC_H_INCLUDED_
#define _NGX_EVENT_QUIC_H_INCLUDED_


#include <stdbool.h>

#include <ngx_config.h>
#include <ngx_core.h>

#include <quiche.h>

/* Limit outgoing packets to 1200 bytes. This is the minimum value allowed. */
#define MAX_DATAGRAM_SIZE 1200

typedef struct ngx_quic_s              ngx_quic_t;
typedef struct ngx_quic_connection_s   ngx_quic_connection_t;

struct ngx_quic_s {
    quiche_config              *config;
    ngx_log_t                  *log;
    bool                        pacing;
};

struct ngx_quic_connection_s {
    quiche_conn                *conn;

    ngx_connection_handler_pt   handler;

    uint8_t                    *send_buf;
    size_t                      send_buf_offset;
    uint16_t                    send_buf_size;
    uint16_t                    segment_size;
    uint16_t                    last_segment_size;

    bool                        blocked;
    bool                        pacing;
    quiche_send_info            send_info;
};


ngx_int_t ngx_quic_create_conf(ngx_quic_t *quic);

ngx_int_t ngx_quic_validate_initial(ngx_event_t *ev, u_char *buf,
    ssize_t buf_len);

ngx_int_t ngx_quic_create_connection(ngx_quic_t *quic, ngx_connection_t *c);

ngx_int_t ngx_quic_create_ssl_connection(ngx_ssl_t *ssl, ngx_connection_t *c,
    ngx_uint_t flags);

ngx_int_t ngx_quic_handshake(ngx_connection_t *c);

ngx_int_t ngx_quic_shutdown(ngx_connection_t *c);

void ngx_quic_cleanup_ctx(void *data);

#endif /* _NGX_EVENT_QUIC_H_INCLUDED_ */
