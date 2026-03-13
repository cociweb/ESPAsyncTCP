/*
  Asynchronous TCP library for Espressif MCUs

  Copyright (c) 2016 Hristo Gochkov. All rights reserved.
  This file is part of the esp8266 core for Arduino environment.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
/*
 * Compatibility for BearSSL with LWIP raw tcp mode (http://lwip.wikia.com/wiki/Raw/TCP)
 * Original Code and Inspiration: Slavey Karadzhov
 * Adopted from tcp_axtls.c by Zhenyu Wu @2018/02
 */
#include <async_config.h>

#if ASYNC_TCP_SSL_ENABLED && ASYNC_TCP_SSL_BEARSSL

#include "user_interface.h"

#include <pgmspace.h>
#include "lwip/opt.h"
#include "lwip/tcp.h"
#include "lwip/inet.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>

#include "tcp_bearssl.h"

#ifndef BEARSSL_HEAPDEBUG
#define BEARSSL_HEAPDEBUG   1
#endif

#ifndef BEARSSL_HSDEBUG
#define BEARSSL_HSDEBUG     1
#endif

#ifndef BEARSSL_READDEBUG
#define BEARSSL_READDEBUG   0
#endif

#ifndef BEARSSL_WRITEDEBUG
#define BEARSSL_WRITEDEBUG  0
#endif

#ifndef BEARSSL_TADEBUG
#define BEARSSL_TADEBUG     0
#endif

#ifndef BEARSSL_NETDEBUG
#define BEARSSL_NETDEBUG    1
#endif

#if BEARSSL_HEAPDEBUG
#define HEAP_DEBUG(...) TCP_SSL_DEBUG(__VA_ARGS__)
#else
#define HEAP_DEBUG(...)
#endif

#if BEARSSL_HSDEBUG
#define HS_DEBUG(...) TCP_SSL_DEBUG(__VA_ARGS__)
#else
#define HS_DEBUG(...)
#endif

#if BEARSSL_READDEBUG
#define READ_DEBUG(...) TCP_SSL_DEBUG(__VA_ARGS__)
#else
#define READ_DEBUG(...)
#endif

#if BEARSSL_WRITEDEBUG
#define WRITE_DEBUG(...) TCP_SSL_DEBUG(__VA_ARGS__)
#else
#define WRITE_DEBUG(...)
#endif

#if BEARSSL_TADEBUG
#define TA_DEBUG(...) TCP_SSL_DEBUG(__VA_ARGS__)
#else
#define TA_DEBUG(...)
#endif

#if BEARSSL_NETDEBUG
#define NET_DEBUG(...) TCP_SSL_DEBUG(__VA_ARGS__)
#else
#define NET_DEBUG(...)
#endif

static uint8_t _tcp_ssl_has_client = 0;

SSL_CTX * tcp_ssl_new_server_ctx(const char *cert, const char *private_key_file, const char *password){
  TCP_SSL_DEBUG("Unimplemented\n");
  return NULL;
}

struct tcp_ssl_pcb {
  struct tcp_pcb *tcp;
  SSL_CTX* ssl_ctx;
  SSL* ssl;
  uint8_t type;
  uint16_t handshake_offset;
  struct pbuf *handshake;
  void * arg;
  tcp_ssl_data_cb_t on_data;
  tcp_ssl_handshake_cb_t on_handshake;
  tcp_ssl_error_cb_t on_error;
  tcp_ssl_cert_cb_t on_cert;
  struct tcp_ssl_pcb * next;
};

typedef struct tcp_ssl_pcb tcp_ssl_t;

static tcp_ssl_t * tcp_ssl_array = NULL;

#define HANDSHAKE_RES 100
static tcp_ssl_t * tcp_ssl_hsptr = NULL;
static os_timer_t handshake_timer = {0};
static void tcp_ssl_handshake_pump(void*);

uint8_t tcp_ssl_has_client(){
  return _tcp_ssl_has_client;
}

#define _ASYNCTCP_STRINGIFY(x) #x
#define ASYNCTCP_STRINGIFY(x) _ASYNCTCP_STRINGIFY(x)

#include <StackThunk.h>
#include <bearssl/bearssl.h>

tcp_ssl_t * tcp_ssl_new(struct tcp_pcb *tcp) {
  TCP_SSL_DEBUG("BearSSL %s\n", ASYNCTCP_STRINGIFY(x));
  HEAP_DEBUG("free_heap_size:%5d malloc(tcp_ssl_t):%u\n", system_get_free_heap_size(), sizeof(tcp_ssl_t));
  tcp_ssl_t * new_item = (tcp_ssl_t*)malloc(sizeof(tcp_ssl_t));
  if(!new_item){
    TCP_SSL_DEBUG("tcp_ssl_new: failed to allocate tcp_ssl_t\n");
    return NULL;
  }
  memset(new_item, 0, sizeof(tcp_ssl_t));
  new_item->tcp = tcp;
  new_item->type = TCP_SSL_TYPE_CLIENT_CONNECTED;

  if(tcp_ssl_array){
    new_item->next = tcp_ssl_array;
  } else {
    os_timer_setfn(&handshake_timer, tcp_ssl_handshake_pump, NULL);
    os_timer_arm(&handshake_timer, HANDSHAKE_RES, true);
  }
  tcp_ssl_array = new_item;
  return new_item;
}

tcp_ssl_t* tcp_ssl_get(struct tcp_pcb *tcp) {
  if(!tcp) {
    return NULL;
  }
  tcp_ssl_t * item = tcp_ssl_array;
  while(item && item->tcp != tcp){
    item = item->next;
  }
  return item;
}

void tcp_ssl_ctx_free(SSL_CTX* ctx) {
    ctx->_iobuf_out = nullptr;
    ctx->_iobuf_in = nullptr;
    stack_thunk_del_ref();
    free(ctx);
}

static SSL_CTX* tcp_ssl_ctx_new(SSL_CTX_PARAMS& params) {
    HEAP_DEBUG("free heap = %5d\n", system_get_free_heap_size());
    HEAP_DEBUG("malloc(SSL_CTX) %d\n", sizeof(SSL_CTX));
    SSL_CTX* ssl_ctx = (SSL_CTX*) malloc(sizeof(SSL_CTX));
    if(!ssl_ctx){
        TCP_SSL_DEBUG("ssl_ctx_new: failed to allocate ssl context buffer\n");
        return nullptr;
    }
    memset(ssl_ctx, 0, sizeof(SSL_CTX));

    HEAP_DEBUG("free heap = %5d\n", system_get_free_heap_size());
    HEAP_DEBUG("malloc(iobuf) in=%u out=%u\n", params.iobuf_in_size, params.iobuf_out_size);

    // XXX: only 4 possible params here, need enum / adjustment on the fly?
    if (!params.iobuf_in_size) {
        params.iobuf_in_size = BEARSSL_DEFAULT_IN_BUF_SIZE;
    }
    if (!params.iobuf_out_size) {
        params.iobuf_out_size = BEARSSL_DEFAULT_OUT_BUF_SIZE;
    }

    params.display("tcp_ssl_ctx_new()", Serial);

    ssl_ctx->_iobuf_in = std::shared_ptr<unsigned char>(new unsigned char[params.iobuf_in_size], std::default_delete<unsigned char[]>());
    ssl_ctx->_iobuf_out = std::shared_ptr<unsigned char>(new unsigned char[params.iobuf_out_size], std::default_delete<unsigned char[]>());

    if (!ssl_ctx->_iobuf_in || !ssl_ctx->_iobuf_out) {
        TCP_SSL_DEBUG("ssl_ctx_new: failed to allocate io buffers\n");
        tcp_ssl_ctx_free(ssl_ctx);
        return nullptr;
    }

    // TODO: merge ssl_ctx and params (subclass?)
    ssl_ctx->_iobuf_in_size = params.iobuf_in_size;
    ssl_ctx->_iobuf_out_size = params.iobuf_out_size;

    ssl_ctx->_use_insecure = params.use_insecure;
    ssl_ctx->_use_self_signed = params.use_self_signed;
    if (params.fingerprint) {
        memcpy(ssl_ctx->_fingerprint, params.fingerprint, 20);
    }

    stack_thunk_add_ref();

    return ssl_ctx;
}

static void br_ssl_client_install_hashes(br_ssl_engine_context *eng) {
    br_ssl_engine_set_hash(eng, br_md5_ID, &br_md5_vtable);
    br_ssl_engine_set_hash(eng, br_sha1_ID, &br_sha1_vtable);
    br_ssl_engine_set_hash(eng, br_sha224_ID, &br_sha224_vtable);
    br_ssl_engine_set_hash(eng, br_sha256_ID, &br_sha256_vtable);
    br_ssl_engine_set_hash(eng, br_sha384_ID, &br_sha384_vtable);
    br_ssl_engine_set_hash(eng, br_sha512_ID, &br_sha512_vtable);
}

static void br_x509_minimal_install_hashes(br_x509_minimal_context *x509) {
    br_x509_minimal_set_hash(x509, br_md5_ID, &br_md5_vtable);
    br_x509_minimal_set_hash(x509, br_sha1_ID, &br_sha1_vtable);
    br_x509_minimal_set_hash(x509, br_sha224_ID, &br_sha224_vtable);
    br_x509_minimal_set_hash(x509, br_sha256_ID, &br_sha256_vtable);
    br_x509_minimal_set_hash(x509, br_sha384_ID, &br_sha384_vtable);
    br_x509_minimal_set_hash(x509, br_sha512_ID, &br_sha512_vtable);
}

static void br_ssl_client_base_init(br_ssl_client_context *cc, const uint16_t *cipher_list, int cipher_cnt) {
    uint16_t suites[cipher_cnt];
    memcpy_P(suites, cipher_list, cipher_cnt * sizeof(cipher_list[0]));
    br_ssl_client_zero(cc);
    br_ssl_engine_add_flags(&cc->eng, BR_OPT_NO_RENEGOTIATION);  // forbid SSL renegociation, as we free the Private Key after handshake
    br_ssl_engine_set_versions(&cc->eng, BR_TLS10, BR_TLS12);
    br_ssl_engine_set_suites(&cc->eng, suites, (sizeof suites) / (sizeof suites[0]));
    br_ssl_client_set_default_rsapub(cc);
    br_ssl_engine_set_default_rsavrfy(&cc->eng);
#ifndef BEARSSL_SSL_BASIC
    br_ssl_engine_set_default_ecdsa(&cc->eng);
#endif
    br_ssl_client_install_hashes(&cc->eng);
    br_ssl_engine_set_prf10(&cc->eng, &br_tls10_prf);
    br_ssl_engine_set_prf_sha256(&cc->eng, &br_tls12_sha256_prf);
    br_ssl_engine_set_prf_sha384(&cc->eng, &br_tls12_sha384_prf);
    br_ssl_engine_set_default_aes_cbc(&cc->eng);
#ifndef BEARSSL_SSL_BASIC
    br_ssl_engine_set_default_aes_gcm(&cc->eng);
    br_ssl_engine_set_default_aes_ccm(&cc->eng);
    br_ssl_engine_set_default_des_cbc(&cc->eng);
    br_ssl_engine_set_default_chapol(&cc->eng);
#endif
}

static const uint16_t suites_P[] PROGMEM = {
    BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
};

static void br_ssl_install_client_x509_validator(SSL_CTX* ctx) {
    // adapted _installClientX509Validator, detached from WiFiClient
    // X509 minimal validator.  Checks dates, cert chain for trusted CA, etc.
    ctx->_x509_minimal = std::make_shared<br_x509_minimal_context>();
    br_x509_minimal_init(ctx->_x509_minimal.get(), &br_sha256_vtable, NULL, 0);
    br_x509_minimal_set_rsa(ctx->_x509_minimal.get(), br_ssl_engine_get_rsavrfy(ctx->_eng));
    br_x509_minimal_set_ecdsa(ctx->_x509_minimal.get(), br_ssl_engine_get_ec(ctx->_eng), br_ssl_engine_get_ecdsa(ctx->_eng));
    br_x509_minimal_install_hashes(ctx->_x509_minimal.get());

    // pre-defined timestamp instead of getting it dynamically
    if (ctx->_now) {
        // Magic constants convert to x509 times
        br_x509_minimal_set_time(ctx->_x509_minimal.get(), ((uint32_t)ctx->_now) / 86400 + 719528, ((uint32_t)ctx->_now) % 86400);
    }

    // TODO: certstore?
    //if (ctx->_certStore) {
    //    &ctx->_certStore.installCertStore(ctx->_x509_minimal);
    //}

    br_ssl_engine_set_x509(ctx->_eng, &ctx->_x509_minimal->vtable);
}

static SSL* br_ssl_client_new(struct tcp_pcb *tcp, SSL_CTX* ctx) {
    HEAP_DEBUG("free heap = %5d\n", system_get_free_heap_size());
    HEAP_DEBUG("malloc(br_ssl_client_context) %d\n", sizeof(br_ssl_client_context));
    br_ssl_client_context* cc = (br_ssl_client_context*)malloc(sizeof(br_ssl_client_context));
    if(!cc) {
        TCP_SSL_DEBUG("br_ssl_client_new: failed to allocate client context struct\n");
        return nullptr;
    }

    br_ssl_client_zero(cc);

    // reference to the engine from our context
    br_ssl_engine_context *engine = &cc->eng;
    ctx->_eng = engine;

    // base init function from WiFiClientSecure, c/p above.
    // we also need some default hardcoded cipher list, which is static in the source... also copied here
    br_ssl_client_base_init(cc, suites_P, sizeof(suites_P) / sizeof(suites_P[0]));

    // TODO: add knownKey
    if (ctx->_use_insecure) {
        TCP_SSL_DEBUG("br_ssl_client_new: using insecure ctx\n");
        // Use common insecure x509 authenticator
        ctx->_x509_insecure = std::make_shared<struct br_x509_insecure_context>();
        if (!ctx->_x509_insecure) {
          HEAP_DEBUG("OOM ctx->_insecure_ctx\n");
          free(cc);
          return nullptr;
        }
        br_x509_insecure_init(ctx->_x509_insecure.get(), ctx->_use_fingerprint, ctx->_fingerprint, ctx->_use_self_signed);
        br_ssl_engine_set_x509(ctx->_eng, &ctx->_x509_insecure->vtable);
    } else {
        TCP_SSL_DEBUG("br_ssl_client_new: using x509 ctx (NOT IMPLEMENTED YET!)\n");
        // Use X509 validator with certstore list
        br_ssl_install_client_x509_validator(ctx);
    }

    br_ssl_engine_set_buffers_bidi(ctx->_eng,
            ctx->_iobuf_in.get(), ctx->_iobuf_in_size,
            ctx->_iobuf_out.get(), ctx->_iobuf_out_size);

    SSL* ssl = (SSL*)malloc(sizeof(SSL));
    if(!ssl) {
        TCP_SSL_DEBUG("br_ssl_client_new: failed to allocate SSL struct\n");
        return nullptr;
    }

    ssl->_cc = cc;

    return ssl;
}

static int tcp_ssl_outbuf_pump_int(struct tcp_pcb *tcp, tcp_ssl_t* tcp_ssl) {
    SSL_CTX *ctx = tcp_ssl->ssl_ctx;
    br_ssl_engine_context *engine = ctx->_eng;
    if(ctx->_pending_send) {
        ctx->_pending_send = 0;
        br_ssl_engine_flush(engine, 0);
    }

    unsigned state = br_ssl_engine_current_state(engine);
    size_t send_len = 0;
    while (state & BR_SSL_SENDREC) {
        size_t buf_len = 0;
        unsigned char *send_buf = br_ssl_engine_sendrec_buf(engine, &buf_len);
        if(send_buf) {
            unsigned char tcp_len = tcp_sndbuf(tcp);
            size_t to_send = tcp_len > buf_len ? buf_len : tcp_len;
            if(!to_send) break;
            NET_DEBUG("tcp_ssl_outbuf_pump_int: writing %u / %u\n", to_send, buf_len);
            err_t err = tcp_write(tcp, send_buf, to_send, TCP_WRITE_FLAG_COPY);
            // Feed the dog before it bites
            system_soft_wdt_feed();
            if(err < ERR_OK) {
                if(err == ERR_MEM) {
                    TCP_SSL_DEBUG("tcp_ssl_outbuf_pump_int: No memory for %u\n", to_send);
                    to_send = 0;
                } else {
                    TCP_SSL_DEBUG("tcp_ssl_outbuf_pump_int: tcp_write error - %u\n", err);
                    tcp_abort(tcp);
                }
                //br_ssl_engine_sendrec_ack(engine, 0);
                break;
            }
            send_len+= to_send;
            br_ssl_engine_sendrec_ack(engine, to_send);
        }
        state = br_ssl_engine_current_state(engine);
    }

    if(send_len) {
        NET_DEBUG("tcp_ssl_outbuf_pump_int: sending %d to network\n", send_len);
        err_t err = tcp_output(tcp);
        if(err != ERR_OK) {
            TCP_SSL_DEBUG("tcp_ssl_outbuf_pump_int: tcp_output err - %u\n", err);
            tcp_abort(tcp);
        }
    }
    return send_len;
}

int tcp_ssl_new_client(struct tcp_pcb *tcp, const char* hostName) {
  SSL_CTX_PARAMS params{};
  params.display("tcp_ssl_new_client()", Serial);
  return tcp_ssl_new_client_ex(tcp, hostName, params);
}

int tcp_ssl_new_client_ex(struct tcp_pcb *tcp, const char* hostName, SSL_CTX_PARAMS& params) {
  if(!tcp) {
    return ERR_TCP_SSL_INVALID_TCP;
  }

  if(tcp_ssl_get(tcp) != NULL){
    TCP_SSL_DEBUG("tcp_ssl_new_client: tcp_ssl already exists\n");
    return ERR_TCP_SSL_INVALID_SSL_REC;
  }

  tcp_ssl_t* tcp_ssl = tcp_ssl_new(tcp);
  if(!tcp_ssl){
    TCP_SSL_DEBUG("tcp_ssl_new_client: failed to allocate tcp-ssl record\n");
    return ERR_TCP_SSL_OUTOFMEMORY;
  }

  tcp_ssl->ssl_ctx = tcp_ssl_ctx_new(params);
  if(!tcp_ssl->ssl_ctx){
    TCP_SSL_DEBUG("tcp_ssl_new_client: failed to allocate ssl context\n");
    return ERR_TCP_SSL_OUTOFMEMORY;
  }

  tcp_ssl->ssl = br_ssl_client_new(tcp, tcp_ssl->ssl_ctx);
  if(!tcp_ssl->ssl){
    TCP_SSL_DEBUG("tcp_ssl_new_client: failed to allocate ssl client\n");
    return ERR_TCP_SSL_OUTOFMEMORY;
  }

  if(!br_ssl_client_reset(tcp_ssl->ssl->_cc, hostName, 0)) {
    TCP_SSL_DEBUG("tcp_ssl_new_client: failed to reset\n");
    return ERR_TCP_SSL_INVALID_SSL_STATE;
  }

  tcp_ssl_outbuf_pump_int(tcp, tcp_ssl);
  return 0;
}

int tcp_ssl_new_server(struct tcp_pcb *tcp, SSL_CTX* ssl_ctx){
  TCP_SSL_DEBUG("Unimplemented\n");
  return -1;
}

int tcp_ssl_free(struct tcp_pcb *tcp) {
  if(!tcp) {
    TCP_SSL_DEBUG("tcp_ssl_free: invalid tcp!\n");
    return ERR_TCP_SSL_INVALID_TCP;
  }

  tcp_ssl_t * prev = NULL;
  tcp_ssl_t * cur = tcp_ssl_array;

  while(cur && cur->tcp != tcp) {
    prev = cur;
    cur = cur->next;
  }

  if(!cur){
    TCP_SSL_DEBUG("tcp_ssl_free: tcp-ssl not found!\n");
    return ERR_TCP_SSL_INVALID_SSL_REC;
  }

  if(prev) {
    prev->next = cur->next;
  } else {
    tcp_ssl_array = cur->next;
  }
  if(cur == tcp_ssl_hsptr) {
    tcp_ssl_hsptr = cur->next? cur->next : tcp_ssl_array;
  }
  if(cur->handshake) {
    pbuf_free(cur->handshake);
  }
  if(cur->ssl) {
    free(cur->ssl);
  }
  if((cur->type & TCP_SSL_TYPE_CLIENT_ALL) && cur->ssl_ctx) {
    tcp_ssl_ctx_free(cur->ssl_ctx);
  }
  if(cur->type & TCP_SSL_TYPE_SERVER_ALL) {
    _tcp_ssl_has_client = 0;
  }
  free(cur);

  if(!tcp_ssl_array) {
    os_timer_disarm(&handshake_timer);
  }
  return 0;
}

int tcp_ssl_write(struct tcp_pcb *tcp, uint8_t *data, size_t len) {
  if(!tcp) {
    return ERR_TCP_SSL_INVALID_TCP;
  }
  if(!data) {
    TCP_SSL_DEBUG("tcp_ssl_write: data == NULL\n");
    return ERR_TCP_SSL_INVALID_APP_DATA;
  }

  tcp_ssl_t * tcp_ssl = tcp_ssl_get(tcp);
  if(!tcp_ssl){
    TCP_SSL_DEBUG("tcp_ssl_write: tcp_ssl is NULL\n");
    return ERR_TCP_SSL_INVALID_SSL_REC;
  }

  SSL_CTX *ctx = tcp_ssl->ssl_ctx;
  br_ssl_engine_context *engine = ctx->_eng;
  unsigned state = br_ssl_engine_current_state(engine);
  if((state & BR_SSL_SENDAPP) == 0) {
    TCP_SSL_DEBUG("tcp_ssl_write: not ready for send\n");
    return 0;
  }

  size_t sendapp_len;
  size_t to_send;
  unsigned char *sendapp_buf = br_ssl_engine_sendapp_buf(engine, &sendapp_len);

  if(sendapp_buf) {
    to_send = len > sendapp_len ? sendapp_len : len;
    memcpy(sendapp_buf, data, to_send);
    br_ssl_engine_sendapp_ack(engine, to_send);
    ctx->_pending_send += to_send;
    WRITE_DEBUG("tcp_ssl_write: request %u, wrote %u\r\n", len, to_send);
    if(sendapp_len == to_send) {
        // when app buffer is filled, flush is done automatically
        ctx->_pending_send = 0;
        return tcp_ssl_outbuf_pump_int(tcp, tcp_ssl);
    }
  }
  return 0;
}

int tcp_ssl_outbuf_pump(struct tcp_pcb *tcp) {
    if(!tcp) {
        return ERR_TCP_SSL_INVALID_TCP;
    }

    tcp_ssl_t * tcp_ssl = tcp_ssl_get(tcp);
    if(!tcp_ssl){
        TCP_SSL_DEBUG("tcp_ssl_outbuf_pump: tcp_ssl is NULL\n");
        return ERR_TCP_SSL_INVALID_SSL_REC;
    }

    return tcp_ssl_outbuf_pump_int(tcp, tcp_ssl);
}

static bool tcp_ssl_handshake_consume(struct tcp_ssl_pcb *tcp_ssl, int amount) {
    struct pbuf *pbuf_handshake = tcp_ssl->handshake;
    int offset_new = tcp_ssl->handshake_offset + amount;
    while (tcp_ssl->handshake) {
        int head_len = tcp_ssl->handshake->len;
        if(head_len > offset_new) {
            tcp_ssl->handshake_offset = offset_new;
            break;
        }
        struct pbuf *head = tcp_ssl->handshake;
        tcp_ssl->handshake = tcp_ssl->handshake->next;
        offset_new -= head_len;
        if (!tcp_ssl->handshake) {
            if (offset_new) {
                // Should not reach!
                HS_DEBUG("tcp_ssl_handshake_consume: over-consumed by %d\n",
                    offset_new);
            }
            tcp_ssl->handshake_offset = 0;
        } else {
            pbuf_ref(tcp_ssl->handshake);
        }
        HS_DEBUG("tcp_ssl_handshake_consume: discarding pbuf of %d\n",
            head_len);
        pbuf_free(head);
    }
    return pbuf_handshake != tcp_ssl->handshake;
}

static void tcp_ssl_handshake_pump(void*) {
    time_t startTS = micros64();
    if(!tcp_ssl_hsptr)
        tcp_ssl_hsptr = tcp_ssl_array;
    while(tcp_ssl_hsptr){
        struct pbuf *pbuf_handshake = tcp_ssl_hsptr->handshake;
        if(!pbuf_handshake) break;
        int buflen = pbuf_handshake->tot_len - tcp_ssl_hsptr->handshake_offset;
        br_ssl_engine_context *engine = tcp_ssl_hsptr->ssl_ctx->_eng;
        unsigned state = br_ssl_engine_current_state(engine);
        while ((state & BR_SSL_RECVREC) && buflen) {
            size_t _recv_len = 0;
            size_t to_copy = 0;
            unsigned char *recv_buf = br_ssl_engine_recvrec_buf(engine, &_recv_len);
            if(recv_buf) {
                to_copy = _recv_len < buflen ? _recv_len : buflen;
                HS_DEBUG("tcp_ssl_handshake_pump: consuming %d / %d\n",
                    to_copy, buflen);
                to_copy = pbuf_copy_partial(pbuf_handshake, recv_buf, to_copy,
                    tcp_ssl_hsptr->handshake_offset);
                HS_DEBUG("tcp_ssl_handshake_pump: consumed %d\n", to_copy);
                if (tcp_ssl_handshake_consume(tcp_ssl_hsptr,to_copy))
                    pbuf_handshake = tcp_ssl_hsptr->handshake;
                buflen -= to_copy;
                br_ssl_engine_recvrec_ack(engine, to_copy);

                state = br_ssl_engine_current_state(engine);
                if(state & BR_SSL_CLOSED) {
                    int ssl_error = br_ssl_engine_last_error(engine);
                    TCP_SSL_DEBUG("tcp_ssl_handshake_pump: handshake failed (%d)\n",
                        ssl_error);
                    if(tcp_ssl_hsptr->on_error) {
                        tcp_ssl_hsptr->on_error(tcp_ssl_hsptr->arg,
                            tcp_ssl_hsptr->tcp, ssl_error);
                    }
                    tcp_abort(tcp_ssl_hsptr->tcp);
                } else if(state & BR_SSL_SENDAPP) {
                    HS_DEBUG("tcp_ssl_handshake_pump: handshake successful\n");
                    tcp_ssl_hsptr->type = TCP_SSL_TYPE_CLIENT_HANDSHAKED;
                    if(tcp_ssl_hsptr->on_handshake) {
                        tcp_ssl_hsptr->on_handshake(tcp_ssl_hsptr->arg,
                            tcp_ssl_hsptr->tcp, tcp_ssl_hsptr->ssl);
                    }
                } else {
                    time_t execSpan = micros64() - startTS;
                    if (execSpan > HANDSHAKE_RES * 1000) break;
                    continue;
                }
                // Cannot take any more data at this stage
                if(buflen) {
                    HS_DEBUG("tcp_ssl_handshake_pump: "
                        "left-over buffer %d\n", buflen);
                }
                break;
            } else {
                // Should not reach!
                HS_DEBUG("tcp_ssl_handshake_pump: "
                    "engine cannot receive data\n");
                break;
            }
        }
        break;
    }
    if(tcp_ssl_hsptr)
        tcp_ssl_hsptr = tcp_ssl_hsptr->next;
}

/**
 * Reads data from the SSL over TCP stream. Returns decrypted data.
 * @param tcp_pcb *tcp - pointer to the raw tcp object
 * @param pbuf *p - pointer to the buffer with the TCP packet data
 *
 * @return int
 *      0 - when everything is fine but there are no symbols to process yet
 *      < 0 - when there is an error
 *      > 0 - the length of the clear text characters that were read
 */

int tcp_ssl_read(struct tcp_pcb *tcp, struct pbuf *p) {
  if(!tcp) {
    return ERR_TCP_SSL_INVALID_TCP;
  }
  if(!p) {
    TCP_SSL_DEBUG("tcp_ssl_read: p == NULL\n");
    return ERR_TCP_SSL_INVALID_TCP_DATA;
  }

  tcp_ssl_t* tcp_ssl = tcp_ssl_get(tcp);
  if(!tcp_ssl) {
    pbuf_free(p);
    TCP_SSL_DEBUG("tcp_ssl_read: tcp_ssl is NULL\n");
    return ERR_TCP_SSL_INVALID_SSL_REC;
  }

  br_ssl_engine_context *engine = tcp_ssl->ssl_ctx->_eng;
  unsigned state = br_ssl_engine_current_state(engine);
  if((state & BR_SSL_RECVREC) == 0) {
    TCP_SSL_DEBUG("tcp_ssl_read: not ready for recv\n");
    return SSL_CANNOT_READ;
  }

  int pbuf_size = p->tot_len;
  if(tcp_ssl->type == TCP_SSL_TYPE_CLIENT_CONNECTED) {
    // We are in handshake stage
    // Computation may be heavy, do not process data here
    NET_DEBUG("tcp_ssl_read: handshake +%d\n", pbuf_size);
    if(!tcp_ssl->handshake) tcp_ssl->handshake = p;
    else pbuf_cat(tcp_ssl->handshake, p);
    tcp_recved(tcp, pbuf_size);
    return pbuf_size;
  }

  int pbuf_offset = 0;
  int total_bytes = 0;
  do {
    size_t _recv_len = 0;
    unsigned char *recv_buf = br_ssl_engine_recvrec_buf(engine, &_recv_len);
    if(recv_buf) {
      int to_copy = _recv_len < pbuf_size ? _recv_len : pbuf_size;
      NET_DEBUG("tcp_ssl_read: consuming %d / %d\n", to_copy, pbuf_size);
      to_copy = pbuf_copy_partial(p, recv_buf, to_copy, pbuf_offset);
      READ_DEBUG("tcp_ssl_read: consumed %d\n", to_copy);
      pbuf_offset += to_copy;
      pbuf_size -= to_copy;
      br_ssl_engine_recvrec_ack(engine, to_copy);
    }
    // Feed the dog before it bites
    system_soft_wdt_feed();
    state = br_ssl_engine_current_state(engine);
    if(state & BR_SSL_RECVAPP) {
      _recv_len = 0;
      unsigned char *recv_buf = br_ssl_engine_recvapp_buf(engine, &_recv_len);
      if(recv_buf) {
        READ_DEBUG("tcp_ssl_read: app data (%d)\n", _recv_len);
        if(tcp_ssl->on_data) {
          tcp_ssl->on_data(tcp_ssl->arg, tcp, recv_buf, _recv_len);
        }
        br_ssl_engine_recvapp_ack(engine, _recv_len);
        total_bytes += _recv_len;
      }
    } else {
      if(state & BR_SSL_CLOSED) {
        int ssl_error = br_ssl_engine_last_error(engine);
        if(ssl_error) {
          TCP_SSL_DEBUG("tcp_ssl_read: connection failed - ");
          TCP_SSL_DEBUG("error (%u)\n", ssl_error);
          tcp_abort(tcp);
        } else {
          TCP_SSL_DEBUG("tcp_ssl_read: connection closed\n");
        }
        total_bytes = SSL_CLOSE_NOTIFY;
        break;
      }
    }
  } while (pbuf_size > 0);

  NET_DEBUG("tcp_ssl_read: processed %d / %d\n", pbuf_offset, p->tot_len);
  tcp_recved(tcp, p->tot_len);
  pbuf_free(p);

  return total_bytes;
}

SSL * tcp_ssl_get_ssl(struct tcp_pcb *tcp){
  tcp_ssl_t * tcp_ssl = tcp_ssl_get(tcp);
  if(tcp_ssl){
    return tcp_ssl->ssl;
  }
  return NULL;
}

bool tcp_ssl_has(struct tcp_pcb *tcp){
  return tcp_ssl_get(tcp) != NULL;
}

int tcp_ssl_is_server(struct tcp_pcb *tcp){
  if(!tcp) {
    return ERR_TCP_SSL_INVALID_TCP;
  }

  tcp_ssl_t * tcp_ssl = tcp_ssl_get(tcp);
  if(!tcp_ssl){
    TCP_SSL_DEBUG("tcp_ssl_write: tcp_ssl is NULL\n");
    return ERR_TCP_SSL_INVALID_SSL_REC;
  }
  return tcp_ssl->type;
}

void tcp_ssl_arg(struct tcp_pcb *tcp, void * arg){
  tcp_ssl_t * item = tcp_ssl_get(tcp);
  if(item) {
    item->arg = arg;
  }
}

void tcp_ssl_data(struct tcp_pcb *tcp, tcp_ssl_data_cb_t arg){
  tcp_ssl_t * item = tcp_ssl_get(tcp);
  if(item) {
    item->on_data = arg;
  }
}

void tcp_ssl_handshake(struct tcp_pcb *tcp, tcp_ssl_handshake_cb_t arg){
  tcp_ssl_t * item = tcp_ssl_get(tcp);
  if(item) {
    item->on_handshake = arg;
  }
}

void tcp_ssl_err(struct tcp_pcb *tcp, tcp_ssl_error_cb_t arg){
  tcp_ssl_t * item = tcp_ssl_get(tcp);
  if(item) {
    item->on_error = arg;
  }
}

void tcp_ssl_cert(struct tcp_pcb *tcp, tcp_ssl_cert_cb_t arg){
  tcp_ssl_t * item = tcp_ssl_get(tcp);
  if(item) {
    item->on_cert = arg;
  }
}

// Stack thunked versions of calls
extern "C" {
extern unsigned char *thunk_br_ssl_engine_recvapp_buf( const br_ssl_engine_context *cc, size_t *len);
extern void thunk_br_ssl_engine_recvapp_ack(br_ssl_engine_context *cc, size_t len);
extern unsigned char *thunk_br_ssl_engine_recvrec_buf( const br_ssl_engine_context *cc, size_t *len);
extern void thunk_br_ssl_engine_recvrec_ack(br_ssl_engine_context *cc, size_t len);
extern unsigned char *thunk_br_ssl_engine_sendapp_buf( const br_ssl_engine_context *cc, size_t *len);
extern void thunk_br_ssl_engine_sendapp_ack(br_ssl_engine_context *cc, size_t len);
extern unsigned char *thunk_br_ssl_engine_sendrec_buf( const br_ssl_engine_context *cc, size_t *len);
extern void thunk_br_ssl_engine_sendrec_ack(br_ssl_engine_context *cc, size_t len);
};


#endif
