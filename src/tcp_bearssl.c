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

#include "lwip/opt.h"
#include "lwip/tcp.h"
#include "lwip/inet.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <tcp_bearssl.h>

static uint8_t _tcp_ssl_has_client = 0;

SSL_CTX * tcp_ssl_new_server_ctx(const char *cert, const char *private_key_file, const char *password){
  TCP_SSL_DEBUG("Unimplemented\n");
  return NULL;
}

struct tcp_ssl_pcb {
  struct tcp_pcb *tcp;
  SSL_CTX* ssl_ctx;
  SSL ssl;
  uint8_t type;
  int handshake;
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

tcp_ssl_t * tcp_ssl_new(struct tcp_pcb *tcp) {
  TCP_SSL_DEBUG("BearSSL %s\n", "(version)");

  tcp_ssl_t * new_item = (tcp_ssl_t*)malloc(sizeof(new_item));
  if(!new_item){
    TCP_SSL_DEBUG("tcp_ssl_new: failed to allocate tcp_ssl\n");
    return NULL;
  }
  memset(new_item, 0, sizeof(new_item));
  new_item->tcp = tcp;
  new_item->handshake = SSL_NOT_OK;
  new_item->type = TCP_SSL_TYPE_CLIENT;

  if(tcp_ssl_array == NULL){
    tcp_ssl_array = new_item;
  } else {
    tcp_ssl_t * item = tcp_ssl_array;
    while(item->next != NULL)
      item = item->next;
    item->next = new_item;
  }

  return new_item;
}

tcp_ssl_t* tcp_ssl_get(struct tcp_pcb *tcp) {
  if(tcp == NULL) {
    return NULL;
  }
  tcp_ssl_t * item = tcp_ssl_array;
  while(item && item->tcp != tcp){
    item = item->next;
  }
  return item;
}

static void ssl_ctx_free(SSL_CTX* ssl_ctx) {
    if (ssl_ctx->_iobuf_in) {
        free(ssl_ctx->_iobuf_in);
    }
    if (ssl_ctx->_iobuf_out) {
        free(ssl_ctx->_iobuf_out);
    }
    free(ssl_ctx);
}

static SSL_CTX* ssl_ctx_new(int _in_buf_size, int _out_buf_size) {
    SSL_CTX* ssl_ctx = (SSL_CTX*) malloc(sizeof(SSL_CTX));
    if(!ssl_ctx){
        TCP_SSL_DEBUG("ssl_ctx_new: failed to allocate ssl context buffer\n");
        return NULL;
    }
    ssl_ctx->_iobuf_in = NULL;
    ssl_ctx->_iobuf_out = NULL;

    ssl_ctx->_iobuf_in = (unsigned char*) malloc(_in_buf_size);
    if(!ssl_ctx->_iobuf_in){
        ssl_ctx_free(ssl_ctx);
        TCP_SSL_DEBUG("ssl_ctx_new: failed to allocate ssl input buffer\n");
        return NULL;
    }
    ssl_ctx->_iobuf_in_size = _in_buf_size;
    ssl_ctx._iobuf_out = (unsigned char*) malloc(_out_buf_size);
    if(!ssl_ctx->_iobuf_out){
        ssl_ctx_free(ssl_ctx);
        TCP_SSL_DEBUG("ssl_ctx_new: failed to allocate ssl output buffer\n");
        return NULL;
    }
    ssl_ctx->_iobuf_out_size = _out_buf_size;

    ssl_ctx->_eng = NULL;
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

static br_x509_trust_anchor* ssl_new_ta(void *dn_hash, size_t dn_hash_len) {
    br_x509_trust_anchor *ta = (br_x509_trust_anchor*)malloc(sizeof(br_x509_trust_anchor));
    if (!ta) {
        TCP_SSL_DEBUG("ssl_new_ta: failed to allocate trust anchor buffer\n");
        return nullptr;
    }
    memset(ta, 0, sizeof(br_x509_trust_anchor));
    ta->dn.data = (uint8_t*)malloc(dn_hash_len);
    if (!ta->dn.data) {
        free(ta);
        TCP_SSL_DEBUG("ssl_new_ta: failed to allocate trust anchor DN data buffer\n");
        return nullptr;
    }
    memcpy(ta->dn.data, dn_hash, dn_hash_len);
    ta->dn.len = dn_hash_len;
    return ta;
}

static void freeHashedTA(const br_x509_trust_anchor *ta) {
    switch (ta->pkey.key_type) {
        case BR_KEYTYPE_RSA:
            free(ta->pkey.key.rsa.e);
            free(ta->pkey.key.rsa.n);
            break;

        case BR_KEYTYPE_EC:
            free(ta->pkey.key.ec.q);
            break;
    }
    free(ta->dn.data);
    free((void*)ta);
}

static const br_x509_trust_anchor *findHashedTA(void *dn_hash, size_t dn_hash_len) {
    uint8_t *certbuf;
    int certlen = _tcp_ssl_cert_cb(_tcp_ssl_cert_arg, dn_hash, dn_hash_len, &certbuf);
    if (certlen) {
        br_x509_decoder_context *dc = new br_x509_decoder_context;
        br_x509_decoder_init(dc, nullptr, nullptr, nullptr, nullptr);
        br_x509_decoder_push(dc, certbuf, certlen);
        free(certbuf);

        br_x509_pkey *pk = br_x509_decoder_get_pkey(dc);
        if (!pk) {
            delete dc;
            TCP_SSL_DEBUG("findHashedTA: failed to get cert public key\n");
            return nullptr;
        }
        br_x509_trust_anchor *ta = ssl_new_ta(dn_hash, dn_hash_len);
        if (!ta) {
            delete dc;
            TCP_SSL_DEBUG("findHashedTA: failed to allocate trust anchor\n");
            return nullptr;
        }
        if (br_x509_decoder_isCA(dc)) {
            ta->flags |= BR_X509_TA_CA;
        }
        delete dc; // Done with x509 decoder

        switch (pk->key_type) {
            case BR_KEYTYPE_RSA:
                ta->pkey.key_type = BR_KEYTYPE_RSA;
                ta->pkey.key.rsa.n = (uint8_t*)malloc(pk->key.rsa.nlen);
                if (!ta->pkey.key.rsa.n) {
                    freeHashedTA(ta);
                    TCP_SSL_DEBUG("findHashedTA: failed to allocate RSA-n\n");
                    return nullptr;
                }
                memcpy(ta->pkey.key.rsa.n, pk->key.rsa.n, pk->key.rsa.nlen);
                ta->pkey.key.rsa.nlen = pk->key.rsa.nlen;
                ta->pkey.key.rsa.e = (uint8_t*)malloc(pk->key.rsa.elen);
                if (!ta->pkey.key.rsa.e) {
                    freeHashedTA(ta->pkey.key.rsa.n);
                    TCP_SSL_DEBUG("findHashedTA: failed to allocate RSA-e\n");
                    return nullptr;
                }
                memcpy(ta->pkey.key.rsa.e, pk->key.rsa.e, pk->key.rsa.elen);
                ta->pkey.key.rsa.elen = pk->key.rsa.elen;
                return ta;

            case BR_KEYTYPE_EC:
                ta->pkey.key_type = BR_KEYTYPE_EC;
                ta->pkey.key.ec.curve = pk->key.ec.curve;
                ta->pkey.key.ec.q = (uint8_t*)malloc(pk->key.ec.qlen);
                if (!ta->pkey.key.ec.q) {
                    freeHashedTA(ta);
                    TCP_SSL_DEBUG("findHashedTA: failed to allocate EC-q\n");
                    return nullptr;
                }
                memcpy(ta->pkey.key.ec.q, pk->key.ec.q, pk->key.ec.qlen);
                ta->pkey.key.ec.qlen = pk->key.ec.qlen;
                return ta;

            default:
                freeHashedTA(ta);
                TCP_SSL_DEBUG("findHashedTA: unrecognised key type\n");
                return nullptr;
        }
    }
    return nullptr;
}

static br_ssl_client_context* br_ssl_client_new(SSL_CTX* ctx, const char* hostName) {
    br_ssl_client_context* cc = (br_ssl_client_context*)malloc(sizeof(br_ssl_client_context));
    if (cc != NULL) {
        uint16_t suites[sizeof(suites_P)/sizeof(uint16_t)];
        memcpy_P(suites, suites_P, sizeof(suites_P));
        br_ssl_client_zero(cc);
        br_ssl_engine_set_versions(&cc->eng, BR_TLS10, BR_TLS12);
        br_ssl_engine_set_suites(&cc->eng, suites, (sizeof suites) / (sizeof suites[0]));
        br_ssl_client_set_default_rsapub(cc);
        br_ssl_engine_set_default_rsavrfy(&cc->eng);
        br_ssl_engine_set_default_ecdsa(&cc->eng);
        for (int id = br_md5_ID; id <= br_sha512_ID; id ++) {
            const br_hash_class *hc;
            hc = hashes[id - 1];
            br_ssl_engine_set_hash(&cc->eng, id, hc);
        }
        br_ssl_engine_set_prf10(&cc->eng, &br_tls10_prf);
        br_ssl_engine_set_prf_sha256(&cc->eng, &br_tls12_sha256_prf);
        br_ssl_engine_set_prf_sha384(&cc->eng, &br_tls12_sha384_prf);
        br_ssl_engine_set_default_aes_cbc(&cc->eng);
        br_ssl_engine_set_default_aes_gcm(&cc->eng);
        br_ssl_engine_set_default_des_cbc(&cc->eng);
        br_ssl_engine_set_default_chapol(&cc->eng);

        ctx->eng = &cc->eng;
        br_x509_minimal_init(ctx->_x509_minimal, &br_sha256_vtable, ctx->_ta, ctx->_ta_num);
        br_x509_minimal_set_rsa(ctx->_x509_minimal, br_ssl_engine_get_rsavrfy(ctx->_eng));
        br_x509_minimal_set_ecdsa(ctx->_x509_minimal, br_ssl_engine_get_ec(ctx->_eng), br_ssl_engine_get_ecdsa(ctx->_eng));
        for (int id = br_md5_ID; id <= br_sha512_ID; id++) {
            const br_hash_class *hc;
            hc = hashes[id - 1];
            br_x509_minimal_set_hash(ctx->_x509_minimal, id, hc);
        }
        br_x509_minimal_set_dynamic(ctx->_x509_minimal, findHashedTA, freeHashedTA);
        br_ssl_engine_set_x509(ctx->_eng, &ctx->_x509_minimal.vtable);
        br_ssl_engine_set_buffers_bidi(ctx->_eng, ctx->_iobuf_in, ctx->_iobuf_in_size, ctx->_iobuf_out, ctx->_iobuf_out_size);
        if (!br_ssl_client_reset(cc, hostName, 0)) {
            free(cc);
            TCP_SSL_DEBUG("br_ssl_client_new: failed to reset\n");
            cc = NULL;
        }
    }
    return cc;
}

void tcp_ssl_outbuf_pump(struct tcp_pcb *tcp, tcp_ssl_t* tcp_ssl) {
    br_ssl_engine_context *engine = tcp_ssl->ssl_ctx->_eng;
    unsigned state = br_ssl_engine_current_state(engine);
    if (state & BR_SSL_SENDREC) {
        size_t send_len;
        unsigned char *send_buf = br_ssl_engine_sendrec_buf(engine, &send_len);
        unsigned char tcp_len = tcp_sndbuf(tcp);
        int to_send = tcp_len > send_len ? send_len : tcp_len;
        err_t err = tcp_write(tcp, send_buf, tcp_len, TCP_WRITE_FLAG_COPY);
        if(err < ERR_OK) {
            if (err == ERR_MEM) {
                TCP_SSL_DEBUG("tcp_ssl_outbuf_pump: No memory %d\n", tcp_len);
            }
            TCP_SSL_DEBUG("tcp_ssl_outbuf_pump: tcp_write error - %d\n", err);
        } else if (err == ERR_OK) {
            TCP_SSL_DEBUG("tcp_ssl_outbuf_pump: tcp_output: %d / %d\n", tcp_len, send_len);
            err = tcp_output(tcp);
            if(err != ERR_OK) {
                TCP_SSL_DEBUG("tcp_ssl_outbuf_pump: tcp_output err - %d\n", err);
                return err;
            }
        }
        br_ssl_engine_sendrec_ack(engine, to_send);
    }
}

int tcp_ssl_new_client(struct tcp_pcb *tcp, int _in_buf_size, int _out_buf_size){
  if(tcp == NULL) {
    return ERR_TCP_SSL_INVALID_TCP;
  }

  if(tcp_ssl_get(tcp) != NULL){
    TCP_SSL_DEBUG("tcp_ssl_new_client: tcp_ssl already exists\n");
    return ERR_TCP_SSL_INVALID_SSL_REC;
  }

  tcp_ssl_t* tcp_ssl = tcp_ssl_new(tcp);
  if(tcp_ssl == NULL){
    TCP_SSL_DEBUG("tcp_ssl_new_client: failed to allocate tcp-ssl record\n");
    return ERR_TCP_SSL_OUTOFMEMORY;
  }

  tcp_ssl->ssl_ctx = ssl_ctx_new(_in_buf_size, _out_buf_size);
  if(tcp_ssl->ssl_ctx == NULL){
    tcp_ssl_free(tcp);
    TCP_SSL_DEBUG("tcp_ssl_new_client: failed to allocate ssl context\n");
    return ERR_TCP_SSL_OUTOFMEMORY;
  }

  tcp_ssl->ssl = br_ssl_client_new(tcp_ssl->ssl_ctx);
  if(tcp_ssl->ssl == NULL){
    tcp_ssl_free(tcp);
    TCP_SSL_DEBUG("tcp_ssl_new_client: failed to allocate ssl\n");
    return ERR_TCP_SSL_OUTOFMEMORY;
  }

  tcp_ssl_outbuf_pump(tcp, tcp_ssl);
  return 0;
}

int tcp_ssl_new_server(struct tcp_pcb *tcp, SSL_CTX* ssl_ctx){
  TCP_SSL_DEBUG("Unimplemented\n");
  return -1;
}

int tcp_ssl_free(struct tcp_pcb *tcp) {
  if(tcp == NULL) {
    return ERR_TCP_SSL_INVALID_TCP;
  }

  tcp_ssl_t * prev = NULL
  tcp_ssl_t * cur = tcp_ssl_array;

  while(cur && cur->tcp != tcp) {
    prev = cur;
    cur = cur->next;
  }

  if(cur == NULL){
    return ERR_TCP_SSL_INVALID_SSL_REC; //item not found
  }

  if (prev) {
    item->next = cur->next;
  } else {
    tcp_ssl_array = cur->next;
  }
  if(cur->tcp_pbuf != NULL){
    pbuf_free(cur->tcp_pbuf);
  }
  if(cur->ssl) {
    free(cur->ssl);
  }
  if(cur->type == TCP_SSL_TYPE_CLIENT && cur->ssl_ctx) {
    ssl_ctx_free(cur->ssl_ctx);
  }
  if(cur->type == TCP_SSL_TYPE_SERVER) {
    _tcp_ssl_has_client = 0;
  }
  free(cur);
  return 0;
}

int tcp_ssl_write(struct tcp_pcb *tcp, uint8_t *data, size_t len) {
  if(tcp == NULL) {
    return ERR_TCP_SSL_INVALID_TCP;
  }
  if(data == NULL) {
    TCP_SSL_DEBUG("tcp_ssl_write: data == NULL\n");
    return ERR_TCP_SSL_INVALID_APP_DATA;
  }

  tcp_ssl_t * tcp_ssl = tcp_ssl_get(tcp);
  if(!tcp_ssl){
    TCP_SSL_DEBUG("tcp_ssl_write: tcp_ssl is NULL\n");
    return ERR_TCP_SSL_INVALID_SSL_REC;
  }

  br_ssl_engine_context *engine = tcp_ssl->ssl_ctx->_eng;
  unsigned state = br_ssl_engine_current_state(engine);
  if ((state & BR_SSL_SENDAPP) == 0) {
    TCP_SSL_DEBUG("tcp_ssl_write: not ready for send\n");
    return 0;
  }

  size_t sendapp_len;
  unsigned char *sendapp_buf = br_ssl_engine_sendapp_buf(engine, &sendapp_len);
  int to_send = len > sendapp_len ? sendapp_len : len;
  memcpy(sendapp_buf, data, to_send);
  br_ssl_engine_sendapp_ack(engine, to_send);
  br_ssl_engine_flush(engine, 0);
  TCP_SSL_DEBUG("tcp_ssl_write: request %u, wrote %u\r\n", len, to_send);

  // Kick-start sending immediately
  tcp_ssl_outbuf_pump(tcp, tcp_ssl);
  return to_send;
}

void tcp_ssl_outbuf_pump(struct tcp_pcb *tcp) {
    if(tcp == NULL) {
        return ERR_TCP_SSL_INVALID_TCP;
    }

    tcp_ssl_t * tcp_ssl = tcp_ssl_get(tcp);
    if(!tcp_ssl){
        TCP_SSL_DEBUG("tcp_ssl_write: tcp_ssl is NULL\n");
        return ERR_TCP_SSL_INVALID_SSL_REC;
    }

    tcp_ssl_outbuf_pump(tcp, tcp_ssl);
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
  if(tcp == NULL) {
    return ERR_TCP_SSL_INVALID_TCP;
  }
  if(p == NULL) {
    TCP_SSL_DEBUG("tcp_ssl_read: p == NULL\n");
    return ERR_TCP_SSL_INVALID_TCP_DATA;
  }

  tcp_ssl_t* tcp_ssl = tcp_ssl_get(tcp);
  if(tcp_ssl == NULL) {
    TCP_SSL_DEBUG("tcp_ssl_read: tcp_ssl is NULL\n");
    return ERR_TCP_SSL_INVALID_SSL_REC;
  }

  br_ssl_engine_context *engine = tcp_ssl->ssl_ctx->_eng;
  unsigned state = br_ssl_engine_current_state(engine);
  if ((state & BR_SSL_RECVREC) == 0) {
    TCP_SSL_DEBUG("tcp_ssl_read: error - not ready for recv\n");
    return ERR_TCP_SSL_INVALID_SSL;
  }

  int pbuf_size = p->tot_len;
  int pbuf_offset = 0;
  int total_bytes = 0;
  do {
    int _recv_len = 0;
    unsigned char *recv_buf = br_ssl_engine_recvrec_buf(engine, &_recv_len);
    if (_recv_len) {
      int to_copy = _recv_len < pbuf_size ? _recv_len : pbuf_size;
	  to_copy = pbuf_copy_partial(p, _recv_buf, to_copy, pbuf_offset);
      br_ssl_engine_recvrec_ack(engine, to_copy);
      pbuf_offset += to_copy;
      pbuf_size -= to_copy;
    }
    state = br_ssl_engine_current_state(engine);
    if (state & BR_SSL_RECVAPP) {
      _recv_len = 0;
      unsigned char *recv_buf = br_ssl_engine_recvapp_buf(engine, &_recv_len);
      if(tcp_ssl->on_data){
        tcp_ssl->on_data(tcp_ssl->arg, tcp, recv_buf, _recv_len);
      }
      br_ssl_engine_recvrec_ack(engine, _recv_len);
      total_bytes += _recv_len;
    } else {
      if (tcp_ssl->handshake != SSL_OK) {
        if (state & BR_SSL_SENDAPP) {
          tcp_ssl->handshake = SSL_OK;
          TCP_SSL_DEBUG("tcp_ssl_read: handshake successful\n");
          if(tcp_ssl->on_handshake)
            tcp_ssl->on_handshake(tcp_ssl->arg, tcp, tcp_ssl->ssl);
        }
        if (state & BR_SSL_CLOSED) {
          int ssl_error = br_ssl_engine_last_error(engine);
          TCP_SSL_DEBUG("tcp_ssl_read: handshake failed (%d)\n", ssl_error);
          if(tcp_ssl->on_error)
            tcp_ssl->on_error(tcp_ssl->arg, tcp, ssl_error);
          return ssl_error;
        }
      }
      if (_recv_len == 0) {
        TCP_SSL_DEBUG("tcp_ssl_read: error - recv record buffer overflow!\n");
        return ERR_TCP_SSL_INVALID_SSL_DATA;
      }
    }
  } while (pbuf_size > 0);

  tcp_recved(tcp, pbuf_offset);
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
  if(tcp == NULL) {
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
