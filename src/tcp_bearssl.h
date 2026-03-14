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
 * Adopted from tcp_axtls.h by Zhenyu Wu @2018/02
 */

#ifndef ASYNCTCP_SSL_BEARSSL_H
#define ASYNCTCP_SSL_BEARSSL_H

#include <async_config.h>

#if ASYNC_TCP_SSL_ENABLED && ASYNC_TCP_SSL_BEARSSL

// Include BearSSL headers for type definitions
#include <bearssl/bearssl.h>

// Make sure br_x509_class is available
#ifndef BR_X509_OK_ID
#include <bearssl/bearssl_x509.h>
#endif

#ifdef __cplusplus
#include "tcp_bearssl_helpers.h"
#include <BearSSLHelpers.h>
#endif

#if BEARSSL_DEBUG
#define DEBUG_BSSL(...) TCP_SSL_DEBUG(__VA_ARGS__)
#else
#define DEBUG_BSSL(...)
#endif

#include "lwipopts.h"

#include <stdbool.h>
#include <bearssl/bearssl.h>

#define ERR_TCP_SSL_INVALID_TCP           -101
#define ERR_TCP_SSL_INVALID_TCP_DATA      -102
#define ERR_TCP_SSL_INVALID_SSL_REC       -103
#define ERR_TCP_SSL_INVALID_SSL_STATE     -104
#define ERR_TCP_SSL_INVALID_SSL_DATA      -105
#define ERR_TCP_SSL_INVALID_APP_DATA      -106
#define ERR_TCP_SSL_OUTOFMEMORY           -107
#define SSL_CLOSE_NOTIFY                  -200
#define SSL_CANNOT_READ                   -201

#define TCP_SSL_TYPE_CLIENT_ALL           0x0F
#define TCP_SSL_TYPE_CLIENT_CONNECTED     0x01
#define TCP_SSL_TYPE_CLIENT_HANDSHAKED    0x02
#define TCP_SSL_TYPE_SERVER_ALL           0xF0

// XXX: this is a dumb c/p from WiFiClientSecure **cpp**
// Private x509 decoder state - simplified version for C/C++ compatibility
struct br_x509_insecure_context {
    void *vtable;  // Use void* instead of br_x509_class*
    bool done_cert;
    const uint8_t *match_fingerprint;
    bool allow_self_signed;
    // Simplified - remove the complex BearSSL context types that are causing issues
    void *sha1_cert;
    void *sha256_subject;
    void *sha256_issuer;
    void *ctx;
};

// Function declaration available for both C and C++
void br_x509_insecure_init(br_x509_insecure_context *ctx, int _use_fingerprint, const uint8_t _fingerprint[20], int _allow_self_signed);

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SSL_ {
  br_ssl_client_context* _cc;
  br_ssl_server_context* _sc;
} SSL;

typedef struct SSL_CTX_ {
  br_ssl_engine_context *_eng;

#ifdef __cplusplus
  std::shared_ptr<br_x509_minimal_context> _x509_minimal;
  std::shared_ptr<struct br_x509_insecure_context> _x509_insecure;
  std::shared_ptr<br_x509_knownkey_context> _x509_knownkey;
  std::shared_ptr<unsigned char> _iobuf_in;
  std::shared_ptr<unsigned char> _iobuf_out;
  std::shared_ptr<uint16_t> _cipher_list;
#else
  // C-compatible raw pointers
  br_x509_minimal_context *_x509_minimal;
  struct br_x509_insecure_context *_x509_insecure;
  br_x509_knownkey_context *_x509_knownkey;
  unsigned char *_iobuf_in;
  unsigned char *_iobuf_out;
  uint16_t *_cipher_list;
#endif

  time_t _now;
#ifdef __cplusplus
  const BearSSL::X509List *_ta;
#else
  const void *_ta;  // C-compatible version
#endif
  int _iobuf_in_size;
  int _iobuf_out_size;
  int _pending_send;

  bool _use_insecure;
  bool _use_fingerprint;
  uint8_t _fingerprint[20];
  bool _use_self_signed;
} SSL_CTX;

typedef void (* tcp_ssl_data_cb_t)(void *arg, struct tcp_pcb *tcp, uint8_t * data, size_t len);
typedef void (* tcp_ssl_handshake_cb_t)(void *arg, struct tcp_pcb *tcp, SSL *ssl);
typedef void (* tcp_ssl_error_cb_t)(void *arg, struct tcp_pcb *tcp, err_t error);
typedef int (* tcp_ssl_cert_cb_t)(void *arg, struct tcp_pcb *tcp, void *dn_hash,
  size_t dn_hash_len, uint8_t **buf);

uint8_t tcp_ssl_has_client();

#define SSL_BUF_OVERHEAD            325
#define SSL_BUF_MINIMUM_DATALEN     512
#define SSL_BUF_NEGOTIATE_DATALEN_0 SSL_BUF_MINIMUM_DATALEN
#define SSL_BUF_NEGOTIATE_DATALEN_1 (SSL_BUF_NEGOTIATE_DATALEN_0 * 2)
#define SSL_BUF_NEGOTIATE_DATALEN_2 (SSL_BUF_NEGOTIATE_DATALEN_1 * 2)
#define SSL_BUF_NEGOTIATE_DATALEN_3 (SSL_BUF_NEGOTIATE_DATALEN_2 * 2)
#define SSL_BUF_DEFAULT_DATALEN     16384
#define SSL_NEGOTIATE_BUF_SIZE_0    (SSL_BUF_NEGOTIATE_DATALEN_0 + SSL_BUF_OVERHEAD)
#define SSL_NEGOTIATE_BUF_SIZE_1    (SSL_BUF_NEGOTIATE_DATALEN_1 + SSL_BUF_OVERHEAD)
#define SSL_NEGOTIATE_BUF_SIZE_2    (SSL_BUF_NEGOTIATE_DATALEN_2 + SSL_BUF_OVERHEAD)
#define SSL_NEGOTIATE_BUF_SIZE_3    (SSL_BUF_NEGOTIATE_DATALEN_3 + SSL_BUF_OVERHEAD)
#define SSL_MINIMUM_BUF_SIZE        SSL_NEGOTIATE_BUF_SIZE_0
#define SSL_DEFAULT_BUF_SIZE        (SSL_BUF_DEFAULT_DATALEN + SSL_BUF_OVERHEAD)

#define BEARSSL_DEFAULT_IN_BUF_SIZE     SSL_DEFAULT_BUF_SIZE
#define BEARSSL_DEFAULT_OUT_BUF_SIZE    SSL_MINIMUM_BUF_SIZE

#ifdef __cplusplus
// C++ version with reference parameter
int tcp_ssl_new_client_ex(struct tcp_pcb *tcp, const char* hostName, SSL_CTX_PARAMS& params);
#else
// C-compatible version
typedef struct {
  bool use_insecure;
  bool use_self_signed;
  int iobuf_in_size;
  int iobuf_out_size;
} tcp_ssl_params_t;

int tcp_ssl_new_client_ex(struct tcp_pcb *tcp, const char* hostName, const tcp_ssl_params_t* params);
#endif

int tcp_ssl_new_client(struct tcp_pcb *tcp, const char* hostName);

SSL_CTX * tcp_ssl_new_server_ctx(const char *cert, const char *private_key_file, const char *password);
int tcp_ssl_new_server(struct tcp_pcb *tcp, SSL_CTX* ssl_ctx);
int tcp_ssl_is_server(struct tcp_pcb *tcp);

int tcp_ssl_free(struct tcp_pcb *tcp);
int tcp_ssl_read(struct tcp_pcb *tcp, struct pbuf *p);

int tcp_ssl_write(struct tcp_pcb *tcp, uint8_t *data, size_t len);
int tcp_ssl_outbuf_pump(struct tcp_pcb *tcp);

void tcp_ssl_arg(struct tcp_pcb *tcp, void * arg);
void tcp_ssl_data(struct tcp_pcb *tcp, tcp_ssl_data_cb_t arg);
void tcp_ssl_handshake(struct tcp_pcb *tcp, tcp_ssl_handshake_cb_t arg);
void tcp_ssl_err(struct tcp_pcb *tcp, tcp_ssl_error_cb_t arg);
void tcp_ssl_cert(struct tcp_pcb *tcp, tcp_ssl_cert_cb_t arg);

SSL * tcp_ssl_get_ssl(struct tcp_pcb *tcp);
void tcp_ssl_ctx_free(SSL_CTX* ssl_ctx);
bool tcp_ssl_has(struct tcp_pcb *tcp);

#ifdef __cplusplus
}
#endif

#endif /* ASYNC_TCP_SSL_ENABLED */

#endif /* ASYNCTCP_SSL_BEARSSL_H */
