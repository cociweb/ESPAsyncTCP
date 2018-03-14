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

#include "pgmspace.h"
#include "lwip/opt.h"
#include "lwip/tcp.h"
#include "lwip/inet.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>

#include <tcp_bearssl.h>
#include "brssl.h"

#define BEARSSL_ALTSTACK 0

#ifndef BEARSSL_HEAPDEBUG
#define BEARSSL_HEAPDEBUG   0
#endif

#ifndef BEARSSL_READDEBUG
#define BEARSSL_READDEBUG   1
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

static void ets_puts_P(const char *romString) {
    char c = pgm_read_byte(romString++);
    while (c) {
        ets_putc(c);
        c = pgm_read_byte(romString++);
    }
}

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
  uint8_t handshake;
  void * arg;
  tcp_ssl_data_cb_t on_data;
  tcp_ssl_handshake_cb_t on_handshake;
  tcp_ssl_error_cb_t on_error;
  struct tcp_ssl_pcb * next;
};

typedef struct tcp_ssl_pcb tcp_ssl_t;

static tcp_ssl_t * tcp_ssl_array = NULL;

uint8_t tcp_ssl_has_client(){
  return _tcp_ssl_has_client;
}

#if BEARSSL_ALTSTACK
#define BEARSSL_STACKSIZE 4500
uint8_t* _bearssl_stack = NULL;
#endif

tcp_ssl_t * tcp_ssl_new(struct tcp_pcb *tcp) {
  TCP_SSL_DEBUG("BearSSL %s\n", "(version)");
  HEAP_DEBUG("free heap = %5d\n", system_get_free_heap_size());
  HEAP_DEBUG("malloc(tcp_ssl_t) %d\n", sizeof(tcp_ssl_t));
  tcp_ssl_t * new_item = (tcp_ssl_t*)malloc(sizeof(tcp_ssl_t));
  if(!new_item){
    TCP_SSL_DEBUG("tcp_ssl_new: failed to allocate tcp_ssl\n");
    return NULL;
  }
  memset(new_item, 0, sizeof(tcp_ssl_t));
  new_item->tcp = tcp;
  new_item->type = TCP_SSL_TYPE_CLIENT;

  if(tcp_ssl_array){
    new_item->next = tcp_ssl_array;
  } else {
#if BEARSSL_ALTSTACK
    HEAP_DEBUG("free heap = %5d\n", system_get_free_heap_size());
    HEAP_DEBUG("malloc(Alt-stack) %d\n", BEARSSL_STACKSIZE);
    _bearssl_stack = (uint8_t*)malloc(BEARSSL_STACKSIZE);
    if (_bearssl_stack) {
      br_esp8266_stack_proxy_init(_bearssl_stack, BEARSSL_STACKSIZE);
    } else {
      TCP_SSL_DEBUG("tcp_ssl_new: failed to allocate bearssl alt-stack\n");
      free(new_item);
      return NULL;
    }
#endif
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

void tcp_ssl_ctx_free(SSL_CTX* ssl_ctx) {
    if (ssl_ctx->_iobuf_out) {
        free(ssl_ctx->_iobuf_out);
    }
    if (ssl_ctx->_iobuf_in) {
        free(ssl_ctx->_iobuf_in);
    }
    free(ssl_ctx);
}

static SSL_CTX* tcp_ssl_ctx_new(int _in_buf_size, int _out_buf_size) {
    HEAP_DEBUG("free heap = %5d\n", system_get_free_heap_size());
    HEAP_DEBUG("malloc(SSL_CTX) %d\n", sizeof(SSL_CTX));
    SSL_CTX* ssl_ctx = (SSL_CTX*) malloc(sizeof(SSL_CTX));
    if(!ssl_ctx){
        TCP_SSL_DEBUG("ssl_ctx_new: failed to allocate ssl context buffer\n");
        return NULL;
    }
    memset(ssl_ctx, 0, sizeof(SSL_CTX));

    HEAP_DEBUG("free heap = %5d\n", system_get_free_heap_size());
    HEAP_DEBUG("malloc(In-buf) %d\n", _in_buf_size);
    ssl_ctx->_iobuf_in = (unsigned char*) malloc(_in_buf_size);
    if(!ssl_ctx->_iobuf_in){
        tcp_ssl_ctx_free(ssl_ctx);
        TCP_SSL_DEBUG("ssl_ctx_new: failed to allocate ssl input buffer\n");
        return NULL;
    }
    HEAP_DEBUG("free heap = %5d\n", system_get_free_heap_size());
    HEAP_DEBUG("malloc(Out-buf) %d\n", _out_buf_size);
    ssl_ctx->_iobuf_in_size = _in_buf_size;
    ssl_ctx->_iobuf_out = (unsigned char*) malloc(_out_buf_size);
    if(!ssl_ctx->_iobuf_out){
        tcp_ssl_ctx_free(ssl_ctx);
        TCP_SSL_DEBUG("ssl_ctx_new: failed to allocate ssl output buffer\n");
        return NULL;
    }
    ssl_ctx->_iobuf_out_size = _out_buf_size;

    return ssl_ctx;
}

static const uint16_t suites_P[] PROGMEM = {
    BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
    BR_TLS_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_RSA_WITH_AES_256_CBC_SHA256,
    BR_TLS_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_RSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_RSA_WITH_3DES_EDE_CBC_SHA
};
static const br_hash_class *hashes[] = {
    &br_md5_vtable,
    &br_sha1_vtable,
    &br_sha224_vtable,
    &br_sha256_vtable,
    &br_sha384_vtable,
    &br_sha512_vtable
};

static tcp_ssl_cert_cb_t _tcp_ssl_cert_cb = NULL;
static void * _tcp_ssl_cert_arg = NULL;

void tcp_ssl_cert(tcp_ssl_cert_cb_t cb, void * arg){
    _tcp_ssl_cert_cb = cb;
    _tcp_ssl_cert_arg = arg;
}

static br_x509_trust_anchor* ssl_new_ta(void) {
    HEAP_DEBUG("free heap = %5d\n", system_get_free_heap_size());
    HEAP_DEBUG("malloc(br_x509_trust_anchor) %d\n", sizeof(br_x509_trust_anchor));
    br_x509_trust_anchor *ta = (br_x509_trust_anchor*)malloc(sizeof(br_x509_trust_anchor));
    if (!ta) {
        TCP_SSL_DEBUG("ssl_new_ta: failed to allocate trust anchor buffer\n");
        return NULL;
    }
    memset(ta, 0, sizeof(br_x509_trust_anchor));
    return ta;
}

static void freeHashedTA(void *ctx, const br_x509_trust_anchor *ta) {
    switch (ta->pkey.key_type) {
        case BR_KEYTYPE_RSA:
            if (ta->pkey.key.rsa.e) free(ta->pkey.key.rsa.e);
            if (ta->pkey.key.rsa.n) free(ta->pkey.key.rsa.n);
            break;

        case BR_KEYTYPE_EC:
            if (ta->pkey.key.ec.q) free(ta->pkey.key.ec.q);
            break;
    }
    free((void*)ta);
}

static const br_x509_trust_anchor *findHashedTA(void *ctx, void *dn_hash, size_t dn_hash_len) {
    TA_DEBUG("findHashedTA: finding trusted certificate...\n");
    uint8_t *certbuf;
    int certlen = 0;
    if (_tcp_ssl_cert_cb) {
        certlen = _tcp_ssl_cert_cb(_tcp_ssl_cert_arg, (struct tcp_pcb *)ctx, dn_hash, dn_hash_len, &certbuf);
    }
    if (certlen) {
        // Feed the dog before it bites
        system_soft_wdt_feed();
        HEAP_DEBUG("free heap = %5d\n", system_get_free_heap_size());
        HEAP_DEBUG("malloc(br_x509_decoder_context) %d\n", sizeof(br_x509_decoder_context));
        br_x509_decoder_context *dc =(br_x509_decoder_context*)malloc(sizeof(br_x509_decoder_context));
        if (!dc) {
            TCP_SSL_DEBUG("findHashedTA: failed to create x509 decoder\n");
            return NULL;
        }
        br_x509_decoder_init(dc, NULL, NULL, NULL, NULL);
        br_x509_decoder_push(dc, certbuf, certlen);

        br_x509_trust_anchor *ta = NULL;
        do {
            br_x509_pkey *pk = br_x509_decoder_get_pkey(dc);
            if (!pk) {
                TCP_SSL_DEBUG("findHashedTA: failed to get cert public key\n");
                break;
            }
            TA_DEBUG("Creating new trust anchor...\n");
            ta = ssl_new_ta();
            if (!ta) {
                TCP_SSL_DEBUG("findHashedTA: failed to allocate trust anchor\n");
                break;
            }
            if (br_x509_decoder_isCA(dc)) {
                ta->flags |= BR_X509_TA_CA;
            }

            switch (pk->key_type) {
                case BR_KEYTYPE_RSA:
                    ta->pkey.key_type = BR_KEYTYPE_RSA;
                    HEAP_DEBUG("free heap = %5d\n", system_get_free_heap_size());
                    HEAP_DEBUG("malloc(RSA-n) %d\n", pk->key.rsa.nlen);
                    //{char a[32]; sprintf(a,"malloc(RSA-n) %d\n", pk->key.rsa.nlen); ets_puts_P(a);}
                    ta->pkey.key.rsa.n = (uint8_t*)malloc(pk->key.rsa.nlen);
                    if (!ta->pkey.key.rsa.n) {
                        freeHashedTA(ctx, ta);
                        ta = NULL;
                        TCP_SSL_DEBUG("findHashedTA: failed to allocate RSA-n\n");
                        break;
                    }
                    memcpy(ta->pkey.key.rsa.n, pk->key.rsa.n, pk->key.rsa.nlen);
                    ta->pkey.key.rsa.nlen = pk->key.rsa.nlen;
                    HEAP_DEBUG("free heap = %5d\n", system_get_free_heap_size());
                    HEAP_DEBUG("malloc(RSA-e) %d\n", pk->key.rsa.elen);
                    //{char a[32]; sprintf(a,"malloc(RSA-e): %d\n", pk->key.rsa.elen); ets_puts_P(a);}
                    ta->pkey.key.rsa.e = (uint8_t*)malloc(pk->key.rsa.elen);
                    if (!ta->pkey.key.rsa.e) {
                        freeHashedTA(ctx, ta);
                        ta = NULL;
                        ets_puts_P("findHashedTA: failed to allocate RSA-e\n");
                        break;
                    }
                    memcpy(ta->pkey.key.rsa.e, pk->key.rsa.e, pk->key.rsa.elen);
                    ta->pkey.key.rsa.elen = pk->key.rsa.elen;
                    break;

                case BR_KEYTYPE_EC:
                    ta->pkey.key_type = BR_KEYTYPE_EC;
                    ta->pkey.key.ec.curve = pk->key.ec.curve;
                    HEAP_DEBUG("free heap = %5d\n", system_get_free_heap_size());
                    HEAP_DEBUG("malloc(EC-q) %d\n", pk->key.ec.qlen);
                    //{char a[32]; sprintf(a,"malloc(EC-q): %d\n", pk->key.ec.qlen); ets_puts_P(a);}
                    ta->pkey.key.ec.q = (uint8_t*)malloc(pk->key.ec.qlen);
                    if (!ta->pkey.key.ec.q) {
                        freeHashedTA(ctx, ta);
                        ta = NULL;
                        TCP_SSL_DEBUG("findHashedTA: failed to allocate EC-q\n");
                        break;
                    }
                    memcpy(ta->pkey.key.ec.q, pk->key.ec.q, pk->key.ec.qlen);
                    ta->pkey.key.ec.qlen = pk->key.ec.qlen;
                    break;

                default:
                    freeHashedTA(ctx, ta);
                    ta = NULL;
                    TCP_SSL_DEBUG("findHashedTA: unrecognised key type (%d)\n", pk->key_type);
                    //{char a[32]; sprintf(a,"key type: %d\n", pk->key_type); ets_puts_P(a);}
            }
        } while(false);

        free(dc);
        return ta;
    }
    return NULL;
}

static br_ssl_client_context* br_ssl_client_new(struct tcp_pcb *tcp, SSL_CTX* ctx) {
    HEAP_DEBUG("free heap = %5d\n", system_get_free_heap_size());
    HEAP_DEBUG("malloc(br_ssl_client_context) %d\n", sizeof(br_ssl_client_context));
    br_ssl_client_context* cc = (br_ssl_client_context*)malloc(sizeof(br_ssl_client_context));
    if (cc != NULL) {
        br_ssl_client_zero(cc);
        br_ssl_engine_context *engine = &cc->eng;

        br_ssl_engine_set_versions(engine, BR_TLS10, BR_TLS12);
        {
            uint16_t suites[sizeof(suites_P)/sizeof(uint16_t)];
            memcpy_P(suites, suites_P, sizeof(suites_P));
            br_ssl_engine_set_suites(engine, suites, sizeof(suites)/sizeof(uint16_t));
        }
        br_ssl_client_set_default_rsapub(cc);
        br_ssl_engine_set_default_rsavrfy(engine);
        br_ssl_engine_set_default_ecdsa(engine);
        for (int id = br_md5_ID; id <= br_sha512_ID; id ++) {
            const br_hash_class *hc;
            hc = hashes[id - 1];
            br_ssl_engine_set_hash(engine, id, hc);
        }
        br_ssl_engine_set_prf10(engine, &br_tls10_prf);
        br_ssl_engine_set_prf_sha256(engine, &br_tls12_sha256_prf);
        br_ssl_engine_set_prf_sha384(engine, &br_tls12_sha384_prf);
        br_ssl_engine_set_default_aes_cbc(engine);
        br_ssl_engine_set_default_aes_gcm(engine);
        br_ssl_engine_set_default_des_cbc(engine);
        br_ssl_engine_set_default_chapol(engine);

        ctx->_eng = engine;
        br_x509_minimal_init(&ctx->_x509_minimal, &br_sha256_vtable, NULL, 0);
        br_x509_minimal_set_rsa(&ctx->_x509_minimal, br_ssl_engine_get_rsavrfy(engine));
        br_x509_minimal_set_ecdsa(&ctx->_x509_minimal, br_ssl_engine_get_ec(engine), br_ssl_engine_get_ecdsa(engine));
        for (int id = br_md5_ID; id <= br_sha512_ID; id++) {
            const br_hash_class *hc;
            hc = hashes[id - 1];
            br_x509_minimal_set_hash(&ctx->_x509_minimal, id, hc);
        }
        br_x509_minimal_set_dynamic(&ctx->_x509_minimal, tcp, findHashedTA, freeHashedTA);
        br_ssl_engine_set_x509(engine, &ctx->_x509_minimal.vtable);
        br_ssl_engine_set_buffers_bidi(engine, ctx->_iobuf_in, ctx->_iobuf_in_size, ctx->_iobuf_out, ctx->_iobuf_out_size);
    }
    return cc;
}

int tcp_ssl_outbuf_pump_int(struct tcp_pcb *tcp, tcp_ssl_t* tcp_ssl) {
    SSL_CTX *ctx = tcp_ssl->ssl_ctx;
    br_ssl_engine_context *engine = ctx->_eng;
    if (ctx->_pending_send) {
        ctx->_pending_send = 0;
        br_ssl_engine_flush(engine, 0);
    }

    unsigned state = br_ssl_engine_current_state(engine);
    size_t send_len = 0;
    while (state & BR_SSL_SENDREC) {
        size_t buf_len = 0;
        unsigned char *send_buf = br_ssl_engine_sendrec_buf(engine, &buf_len);
        if (send_buf) {
            unsigned char tcp_len = tcp_sndbuf(tcp);
            int to_send = tcp_len > buf_len ? buf_len : tcp_len;
            if (!to_send) break;
            NET_DEBUG("tcp_ssl_outbuf_pump_int: writing %d / %d\n", to_send, buf_len);
            err_t err = tcp_write(tcp, send_buf, to_send, TCP_WRITE_FLAG_COPY);
            // Feed the dog before it bites
            system_soft_wdt_feed();
            if(err < ERR_OK) {
                if (err == ERR_MEM) {
                    TCP_SSL_DEBUG("tcp_ssl_outbuf_pump_int: No memory for %d\n", to_send);
                    to_send = 0;
                } else {
                    TCP_SSL_DEBUG("tcp_ssl_outbuf_pump_int: tcp_write error - %d\n", err);
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

    if (send_len) {
        NET_DEBUG("tcp_ssl_outbuf_pump_int: sending %d to network\n", send_len);
        err_t err = tcp_output(tcp);
        if(err != ERR_OK) {
            TCP_SSL_DEBUG("tcp_ssl_outbuf_pump_int: tcp_output err - %d\n", err);
            tcp_abort(tcp);
        }
    }
    return send_len;
}

int tcp_ssl_new_client(struct tcp_pcb *tcp, const char* hostName) {
  return tcp_ssl_new_client_ex(tcp, hostName, BEARSSL_DEFAULT_IN_BUF_SIZE, BEARSSL_DEFAULT_OUT_BUF_SIZE);
}

int tcp_ssl_new_client_ex(struct tcp_pcb *tcp, const char* hostName, int _in_buf_size, int _out_buf_size){
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

  tcp_ssl->ssl_ctx = tcp_ssl_ctx_new(_in_buf_size, _out_buf_size);
  if(!tcp_ssl->ssl_ctx){
    TCP_SSL_DEBUG("tcp_ssl_new_client: failed to allocate ssl context\n");
    return ERR_TCP_SSL_OUTOFMEMORY;
  }

  tcp_ssl->ssl = br_ssl_client_new(tcp, tcp_ssl->ssl_ctx);
  if(!tcp_ssl->ssl){
    TCP_SSL_DEBUG("tcp_ssl_new_client: failed to allocate ssl client\n");
    return ERR_TCP_SSL_OUTOFMEMORY;
  }

  if (!br_ssl_client_reset(tcp_ssl->ssl, hostName, 0)) {
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

  if (prev) {
    prev->next = cur->next;
  } else {
    tcp_ssl_array = cur->next;
  }
  if(cur->ssl) {
    free(cur->ssl);
  }
  if(cur->type == TCP_SSL_TYPE_CLIENT && cur->ssl_ctx) {
    tcp_ssl_ctx_free(cur->ssl_ctx);
  }
  if(cur->type == TCP_SSL_TYPE_SERVER) {
    _tcp_ssl_has_client = 0;
  }
  free(cur);

#if BEARSSL_ALTSTACK
  if (!tcp_ssl_array) {
    free(_bearssl_stack);
    _bearssl_stack = NULL;
  }
#endif
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
  if ((state & BR_SSL_SENDAPP) == 0) {
    TCP_SSL_DEBUG("tcp_ssl_write: not ready for send\n");
    return 0;
  }

  size_t sendapp_len;
  unsigned char *sendapp_buf = br_ssl_engine_sendapp_buf(engine, &sendapp_len);
  if (sendapp_buf) {
    int to_send = len > sendapp_len ? sendapp_len : len;
    memcpy(sendapp_buf, data, to_send);
    br_ssl_engine_sendapp_ack(engine, to_send);
    ctx->_pending_send += to_send;
    WRITE_DEBUG("tcp_ssl_write: request %u, wrote %u\r\n", len, to_send);
    if (sendapp_len == to_send) {
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
        TCP_SSL_DEBUG("tcp_ssl_write: tcp_ssl is NULL\n");
        return ERR_TCP_SSL_INVALID_SSL_REC;
    }

    return tcp_ssl_outbuf_pump_int(tcp, tcp_ssl);
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
  if ((state & BR_SSL_RECVREC) == 0) {
    pbuf_free(p);
    TCP_SSL_DEBUG("tcp_ssl_read: error - not ready for recv\n");
    return ERR_TCP_SSL_INVALID_SSL_STATE;
  }

  int pbuf_size = p->tot_len;
  int pbuf_offset = 0;
  int total_bytes = 0;
  do {
    int _recv_len = 0;
    unsigned char *recv_buf = br_ssl_engine_recvrec_buf(engine, &_recv_len);
    if (recv_buf) {
      int to_copy = _recv_len < pbuf_size ? _recv_len : pbuf_size;
      NET_DEBUG("tcp_ssl_read: consuming %d / %d\n", to_copy, pbuf_size);
      to_copy = pbuf_copy_partial(p, recv_buf, to_copy, pbuf_offset);
      READ_DEBUG("tcp_ssl_read: consumed %d\n", to_copy);
      br_ssl_engine_recvrec_ack(engine, to_copy);
      pbuf_offset += to_copy;
      pbuf_size -= to_copy;
    }
    // Feed the dog before it bites
    system_soft_wdt_feed();
    state = br_ssl_engine_current_state(engine);
    if (state & BR_SSL_RECVAPP) {
      _recv_len = 0;
      unsigned char *recv_buf = br_ssl_engine_recvapp_buf(engine, &_recv_len);
      if (recv_buf) {
        READ_DEBUG("tcp_ssl_read: app data (%d)\n", _recv_len);
        if(tcp_ssl->on_data) {
          tcp_ssl->on_data(tcp_ssl->arg, tcp, recv_buf, _recv_len);
        }
        br_ssl_engine_recvapp_ack(engine, _recv_len);
        total_bytes += _recv_len;
      }
    } else {
      if (state & BR_SSL_CLOSED) {
        if (!tcp_ssl->handshake) {
          TCP_SSL_DEBUG("tcp_ssl_read: handshake failed - ");
          int ssl_error = br_ssl_engine_last_error(engine);
          TCP_SSL_DEBUG_DO(
            const char *desc;
            if (find_error_name(ssl_error, &desc)) {
              ets_puts_P(desc);
              ets_putc('\n');
            } else {
              TCP_SSL_DEBUG("error (%d)\n", ssl_error);
            }
          );
          total_bytes = -1000 - ssl_error;
          break;
        } else {
          int ssl_error = br_ssl_engine_last_error(engine);
          if (ssl_error) {
            TCP_SSL_DEBUG("tcp_ssl_read: connection failed - ");
            TCP_SSL_DEBUG_DO(
              const char *desc;
              if (find_error_name(ssl_error, &desc)) {
                ets_puts_P(desc);
                ets_putc('\n');
              } else {
                TCP_SSL_DEBUG("error (%d)\n", ssl_error);
              }
            )
            tcp_abort(tcp);
          } else {
            TCP_SSL_DEBUG("tcp_ssl_read: connection closed\n");
          }
          total_bytes = SSL_CLOSE_NOTIFY;
          break;
        }
      } else if (state & BR_SSL_SENDAPP) {
        if (!tcp_ssl->handshake) {
          tcp_ssl->handshake = 1;
          READ_DEBUG("tcp_ssl_read: handshake successful\n");
          if(tcp_ssl->on_handshake)
            tcp_ssl->on_handshake(tcp_ssl->arg, tcp, tcp_ssl->ssl);
        }
      }
    }
  } while (pbuf_size > 0);

  NET_DEBUG("tcp_ssl_read: acking %d / %d\n", pbuf_offset, p->tot_len);
  tcp_recved(tcp, pbuf_offset);
  //tcp_recved(tcp, p->tot_len);
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

#endif
