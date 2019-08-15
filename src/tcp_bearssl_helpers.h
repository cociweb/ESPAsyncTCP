#ifndef ASYNCTCP_TCP_BEARSSL_HELPERS_H_
#define ASYNCTCP_TCP_BEARSSL_HELPERS_H_

#include <Stream.h>

#if ASYNC_TCP_SSL_BEARSSL
struct SSL_CTX_PARAMS {
  bool use_insecure = false;
  bool use_self_signed = false;
  int iobuf_in_size = 0;
  int iobuf_out_size = 0;
  uint8_t fingerprint[20];
  void display(const char* tag, Stream& out) {
    out.printf("%s: insecure=%u ss=%u in=%u out=%u\n",
        tag,
        use_insecure, use_self_signed,
        iobuf_in_size, iobuf_out_size);
  }
};

#endif

#endif // ASYNCTCP_TCP_BEARSSL_HELPERS_H_
