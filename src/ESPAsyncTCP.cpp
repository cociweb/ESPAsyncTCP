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
Changes for July 2019

The operator "new ..." was changed to "new (std::nothrow) ...", which will
return NULL when the heap is out of memory. Without the change "soft WDT"
was the result, starting with Arduino ESP8266 Core 2.5.0. (Note, RE:"soft
WDT" - the error  reporting may improve with core 2.6.) With proir core
versions the library appears to work fine.
ref: https://github.com/esp8266/Arduino/issues/6269#issue-464978944

To support newer lwIP versions and buffer models. All references to 1460
were replaced with TCP_MSS. If TCP_MSS is not defined (exp. 1.4v lwIP)
1460 is assumed.

The ESPAsyncTCP library should build for Arduino ESP8266 Core releases:
2.3.0, 2.4.1, 2.4.2, 2.5.1, 2.5.2. It may still build with core versions
2.4.0 and 2.5.0. I did not do any regression testing with these, since
they had too many issues and were quickly superseded.

lwIP tcp_err() callback often resulted in crashes. The problem was a
tcp_err() would come in, while processing a send or receive in the
forground. The tcp_err() callback would be passed down to a client's
registered disconnect CB. A common problem with SyncClient and other
modules as well as some client code was: the freeing of ESPAsyncTCP
AsyncClient objects via disconnect CB handlers while the library was
waiting for an operstion to  finished. Attempts to access bad pointers
followed. For SyncClient this commonly occured during a call to delay().
On return to SyncClient _client was invalid. Also the problem described by
issue #94 also surfaced

Use of tcp_abort() required some very special handling and was very
challenging to make work without changing client API. ERR_ABRT can only be
used once on a return to lwIP for a given connection and since the
AsyncClient structure was sometimes deleted before returning to lwIP, the
state tracking became tricky. While ugly, a global variable for this
seemed to work; however, I  abanded it when I saw a possible
reentrancy/concurrency issue. After several approaches I settled the
problem by creating "class ACErrorTracker" to manage the issue.


Additional Async Client considerations:

The client sketch must always test if the connection is still up at loop()
entry and after the return of any function call, that may have done a
delay() or yield() or any ESPAsyncTCP library family call. For example,
the connection could be lost during a call to _client->write(...). Client
sketches that delete _client as part of their onDisconnect() handler must
be very careful as _client will become invalid after calls to delay(),
yield(), etc.


 */

#include "Arduino.h"

#include "ESPAsyncTCP.h"
extern "C"{
  #include "lwip/opt.h"
  #include "lwip/tcp.h"
  #include "lwip/inet.h"
  #include "lwip/dns.h"
  #include "lwip/init.h"
}
#include "tcp_axtls.h"
#include "tcp_bearssl.h"
#include "tcp_bearssl_helpers.h"

/*
  Async Client Error Return Tracker
*/
// Assumption: callbacks are never called with err == ERR_ABRT; however,
// they may return ERR_ABRT.

ACErrorTracker::ACErrorTracker(AsyncClient *c):
    _client(c)
  , _close_error(ERR_OK)
  , _errored(EE_OK)
#ifdef DEBUG_MORE
  , _error_event_cb(NULL)
  , _error_event_cb_arg(NULL)
#endif
{}

uint32_t ACErrorTracker::getConnectionId(void) const {
  if (_client) {
    return _client->getConnectionId();
  }
  return 0;
}

#ifdef DEBUG_MORE
/**
 * This is not necessary, but a start at gathering some statistics on
 * errored out connections. Used from AsyncServer.
 */
void ACErrorTracker::onErrorEvent(AsNotifyHandler cb, void *arg) {
  _error_event_cb = cb;
  _error_event_cb_arg = arg;
}
#endif

void ACErrorTracker::setCloseError(err_t e) {
  if (e != ERR_OK)
    ASYNC_TCP_DEBUG("setCloseError() to: %s(%d)\n", _client->errorToString(e), e);
  if(_errored == EE_OK)
    _close_error = e;
}
/**
 * Called mainly by callback routines, called when err is not ERR_OK.
 * This prevents the possiblity of aborting an already errored out
 * connection.
 */
void ACErrorTracker::setErrored(size_t errorEvent){
  if(EE_OK == _errored)
    _errored = errorEvent;
#ifdef DEBUG_MORE
  if (_error_event_cb)
    _error_event_cb(_error_event_cb_arg, errorEvent);
#endif
}
/**
 * Used by callback functions only. Used for proper ERR_ABRT return value
 * reporting. ERR_ABRT is only reported/returned once; thereafter ERR_OK
 * is always returned.
 */
err_t ACErrorTracker::getCallbackCloseError(void){
  if (EE_OK != _errored)
    return ERR_OK;
  if (ERR_ABRT == _close_error)
    setErrored(EE_ABORTED);
  return _close_error;
}

/*
  Async TCP Client
*/
#if DEBUG_ESP_ASYNC_TCP
static size_t _connectionCount=0;
#endif

#if ASYNC_TCP_SSL_ENABLED
AsyncClient::AsyncClient(tcp_pcb* pcb, SSL_CTX * ssl_ctx):
#else
AsyncClient::AsyncClient(tcp_pcb* pcb):
#endif
  _connect_cb(0)
  , _connect_cb_arg(0)
  , _discard_cb(0)
  , _discard_cb_arg(0)
  , _sent_cb(0)
  , _sent_cb_arg(0)
  , _error_cb(0)
  , _error_cb_arg(0)
  , _recv_cb(0)
  , _recv_cb_arg(0)
  , _pb_cb(0)
  , _pb_cb_arg(0)
  , _timeout_cb(0)
  , _timeout_cb_arg(0)
  , _poll_cb(0)
  , _poll_cb_arg(0)
  , _pcb_busy(false)
#if ASYNC_TCP_SSL_ENABLED
  , _pcb_secure(false)
  , _handshake_done(true)
  , _handshake_start(0)
  , _handshake_timeout(ASYNC_MAX_HANDSHAKE_TIME)
#if ASYNC_TCP_SSL_BEARSSL
  , _ssl_certlookup_cb(0)
  , _ssl_certlookup_cb_arg(0)
  , _ssl_in_buf_size(BEARSSL_DEFAULT_IN_BUF_SIZE)
  , _ssl_out_buf_size(BEARSSL_DEFAULT_OUT_BUF_SIZE)
#endif
#endif
  , _pcb_sent_at(0)
  , _close_pcb(false)
  , _ack_pcb(true)
  , _tx_unacked_len(0)
  , _tx_acked_len(0)
  , _rx_ack_len(0)
  , _rx_last_packet(0)
  , _rx_since_timeout(0)
  , _ack_timeout(ASYNC_MAX_ACK_TIME)
  , _connect_port(0)
  , _recv_pbuf_flags(0)
  , _errorTracker(NULL)
  , prev(NULL)
  , next(NULL)
{
  _pcb = pcb;
  if(_pcb){
    _rx_last_packet = millis();
    tcp_setprio(_pcb, TCP_PRIO_MIN);
    tcp_arg(_pcb, this);
    tcp_recv(_pcb, &_s_recv);
    tcp_sent(_pcb, &_s_sent);
    tcp_err(_pcb, &_s_error);
    tcp_poll(_pcb, &_s_poll, 1);
#if ASYNC_TCP_SSL_ENABLED
    if(ssl_ctx){
      if(tcp_ssl_new_server(_pcb, ssl_ctx) < 0){
        _close();
        return;
      }
      tcp_ssl_arg(_pcb, this);
      tcp_ssl_data(_pcb, &_s_data);
      tcp_ssl_handshake(_pcb, &_s_handshake);
      tcp_ssl_err(_pcb, &_s_ssl_error);
      tcp_ssl_cert(_pcb, &_s_certlookup);

      _pcb_secure = true;
      _handshake_done = false;
    }
#endif
  }

  _errorTracker = std::make_shared<ACErrorTracker>(this);
#if DEBUG_ESP_ASYNC_TCP
  _errorTracker->setConnectionId(++_connectionCount);
#endif
}

AsyncClient::~AsyncClient(){
  if(_pcb)
    _close();

  _errorTracker->clearClient();
}

inline void clearTcpCallbacks(tcp_pcb* pcb){
      tcp_arg(pcb, NULL);
      tcp_sent(pcb, NULL);
      tcp_recv(pcb, NULL);
      tcp_err(pcb, NULL);
      tcp_poll(pcb, NULL, 0);
}

#if ASYNC_TCP_SSL_ENABLED
bool AsyncClient::connect(IPAddress ip, uint16_t port, bool secure, const char* host){
#else
bool AsyncClient::connect(IPAddress ip, uint16_t port){
#endif
  if(_pcb) //already connected
    return false;
  IPAddress addr;
  addr = ip;
#if LWIP_VERSION_MAJOR == 1
  netif* interface = ip_route(&addr);
  if(!interface){ //no route to host
    return false;
  }
#endif
  tcp_pcb* pcb = tcp_new();
  if(!pcb){ //could not allocate pcb
    return false;
  }

  tcp_setprio(pcb, TCP_PRIO_MIN);
#if ASYNC_TCP_SSL_ENABLED
  _pcb_secure = secure;
  _handshake_done = !secure;
  _hostname = host? host : "";
#endif
  tcp_arg(pcb, this);
  tcp_err(pcb, &_s_error);
  size_t err = tcp_connect(pcb, addr, port,(tcp_connected_fn)&_s_connected);
  return (ERR_OK == err);
}

#if ASYNC_TCP_SSL_ENABLED
bool AsyncClient::connect(const char* host, uint16_t port, bool secure){
#else
bool AsyncClient::connect(const char* host, uint16_t port){
#endif
  IPAddress addr;
  err_t err = dns_gethostbyname(host, addr, (dns_found_callback)&_s_dns_found, this);
  if(err == ERR_OK) {
#if ASYNC_TCP_SSL_ENABLED
    return connect(IPAddress(addr), port, secure, host);
#else
    return connect(addr, port);
#endif
  } else if(err == ERR_INPROGRESS) {
#if ASYNC_TCP_SSL_ENABLED
    _pcb_secure = secure;
    _handshake_done = !secure;
#endif
    _connect_port = port;
    return true;
  }
  return false;
}

AsyncClient& AsyncClient::operator=(const AsyncClient& other){
  if(_pcb)
    _close();
  _errorTracker = other._errorTracker;

  // I am confused when "other._pcb" falls out of scope the destructor will
  // close it? TODO: Look to see where this is used and how it might work.
  _pcb = other._pcb;
  if(_pcb) {
    _rx_last_packet = millis();
    tcp_setprio(_pcb, TCP_PRIO_MIN);
    tcp_arg(_pcb, this);
    tcp_recv(_pcb, &_s_recv);
    tcp_sent(_pcb, &_s_sent);
    tcp_err(_pcb, &_s_error);
    tcp_poll(_pcb, &_s_poll, 1);
#if ASYNC_TCP_SSL_ENABLED
    if(tcp_ssl_has(_pcb)){
      _pcb_secure = true;
      _handshake_done = false;
      tcp_ssl_arg(_pcb, this);
      tcp_ssl_data(_pcb, &_s_data);
      tcp_ssl_handshake(_pcb, &_s_handshake);
      tcp_ssl_err(_pcb, &_s_ssl_error);
      tcp_ssl_cert(_pcb, &_s_certlookup);
    } else {
      _pcb_secure = false;
      _handshake_done = true;
    }
#endif
  }
  return *this;
}

bool AsyncClient::operator==(const AsyncClient &other) {
  return (_pcb != NULL && other._pcb != NULL && (IPAddress(_pcb->remote_ip) ==  IPAddress(other._pcb->remote_ip)) && (_pcb->remote_port == other._pcb->remote_port));
}

void AsyncClient::abort(){
  // Notes:
  // 1) _pcb is set to NULL, so we cannot call tcp_abort() more than once.
  // 2) setCloseError(ERR_ABRT) is only done here!
  // 3) Using this abort() function guarantees only one tcp_abort() call is
  //    made and only one CB returns with ERR_ABORT.
  // 4) After abort() is called from _close(), no callbacks with an err
  //    parameter will be called.  eg. _recv(), _error(), _connected().
  //    _close() will reset there CB handlers before calling.
  // 5) A callback to _error(), will set _pcb to NULL, thus avoiding the
  //    of a 2nd call to tcp_abort().
  // 6) Callbacks to _recv() or _connected() with err set, will result in _pcb
  //    set to NULL. Thus, preventing possible calls later to tcp_abort().
  if(_pcb) {
    tcp_abort(_pcb);
    _pcb = NULL;
    setCloseError(ERR_ABRT);
  }
  return;
}

void AsyncClient::close(bool now){
  if(_pcb)
    tcp_recved(_pcb, _rx_ack_len);
  if(now) {
    ASYNC_TCP_DEBUG("close[%u]: AsyncClient 0x%" PRIXPTR "\n", getConnectionId(), uintptr_t(this));
    _close();
  } else {
    _close_pcb = true;
  }
}

void AsyncClient::stop() {
  close(false);
}

bool AsyncClient::free(){
  if(!_pcb)
    return true;
  if(_pcb->state == 0 || _pcb->state > 4)
    return true;
  return false;
}

size_t AsyncClient::write(const char* data) {
  if(data == NULL)
    return 0;
  return write(data, strlen(data));
}

size_t AsyncClient::write(const char* data, size_t size, uint8_t apiflags) {
  size_t will_send = add(data, size, apiflags);
  if(will_send > 0) {
    if(!send()) return 0;
  }
  return will_send;
}

size_t AsyncClient::add(const char* data, size_t size, uint8_t apiflags) {
  if(!_pcb) return ERR_CONN;
  size_t room = space();
  if(!room || !size) return 0;
  if(!data) return ERR_VAL;
#if ASYNC_TCP_SSL_ENABLED
  if(_pcb_secure){
    int sent = tcp_ssl_write(_pcb, (uint8_t*)data, size);
    if(sent < 0) {
      _close();
      return sent;
    }
    if(sent > 0){
      _pcb_busy = true;
      _pcb_sent_at = millis();
      _tx_unacked_len += sent;
    }
    return size;
  }
#endif
  size_t will_send = (room < size) ? room : size;
  err_t err = tcp_write(_pcb, data, will_send, apiflags);
  if(err != ERR_OK) {
    ASYNC_TCP_DEBUG("_add[%u]: tcp_write() returned err: %s(%d)\n", getConnectionId(), errorToString(err), err);
    return 0;
  }
  _tx_unacked_len += will_send;
  return will_send;
}

bool AsyncClient::send(){
#if ASYNC_TCP_SSL_ENABLED
  if(_pcb_secure) {
    if(_handshake_done) return false;
#if ASYNC_TCP_SSL_BEARSSL
    int pumped = tcp_ssl_outbuf_pump(_pcb);
    if(pumped) {
      _pcb_busy = true;
      _pcb_sent_at = millis();
      _tx_unacked_len += pumped;
    }
    return pumped;
#else
    return true;
#endif
  }
#endif
  err_t err = tcp_output(_pcb);
  if(err == ERR_OK){
    _pcb_busy = true;
    _pcb_sent_at = millis();
    return true;
  }
  ASYNC_TCP_DEBUG("send: tcp_output error %u\n", err);
  //_tx_unsent_len = 0;
  return false;
}

size_t AsyncClient::ack(size_t len){
  if(len > _rx_ack_len)
    len = _rx_ack_len;
  if(len)
    tcp_recved(_pcb, len);
  _rx_ack_len -= len;
  return len;
}

// Private Callbacks

void AsyncClient::_connected(std::shared_ptr<ACErrorTracker>& errorTracker, void* pcb, err_t err){
  //(void)err; // LWIP v1.4 appears to always call with ERR_OK
  // Documentation for 2.1.0 also says:
  //   "err	- An unused error code, always ERR_OK currently ;-)"
  // https://www.nongnu.org/lwip/2_1_x/tcp_8h.html#a939867106bd492caf2d85852fb7f6ae8
  // Based on that wording and emoji lets just handle it now.
  // After all, the API does allow for an err != ERR_OK.
  if(NULL == pcb || ERR_OK != err) {
    ASYNC_TCP_DEBUG("_connected[%u]:%s err: %s(%d)\n", errorTracker->getConnectionId(), ((NULL == pcb) ? " NULL == pcb!," : ""), errorToString(err), err);
    errorTracker->setCloseError(err);
    errorTracker->setErrored(EE_CONNECTED_CB);
    _pcb = reinterpret_cast<tcp_pcb*>(pcb);
    if (_pcb)
      clearTcpCallbacks(_pcb);
    _pcb = NULL;
    _error(err);
    return;
  }

  _pcb = reinterpret_cast<tcp_pcb*>(pcb);
  if(_pcb){
    _pcb_busy = false;
    _tx_unacked_len = 0;
    _tx_acked_len = 0;
    _tx_unsent_len = 0;
    _rx_last_packet = millis();
    tcp_setprio(_pcb, TCP_PRIO_MIN);
    tcp_recv(_pcb, &_s_recv);
    tcp_sent(_pcb, &_s_sent);
    tcp_poll(_pcb, &_s_poll, 1);
#if ASYNC_TCP_SSL_ENABLED
    if(_pcb_secure){
#if ASYNC_TCP_SSL_BEARSSL
      if(tcp_ssl_new_client_ex(_pcb, _hostname.c_str(), _ssl_params)){
#endif
#if ASYNC_TCP_SSL_AXTLS
      if(tcp_ssl_new_client(_pcb) < 0){
#endif
        return _close();
      }
      _handshake_start = _rx_last_packet;
      tcp_ssl_arg(_pcb, this);
      tcp_ssl_data(_pcb, &_s_data);
      tcp_ssl_handshake(_pcb, &_s_handshake);
      tcp_ssl_err(_pcb, &_s_ssl_error);
      tcp_ssl_cert(_pcb, &_s_certlookup);
    }
  }
  if(!_pcb_secure && _connect_cb)
#else
  }
  if(_connect_cb)
#endif
    _connect_cb(_connect_cb_arg, this);
  return;
}

void AsyncClient::_close(){
  if(_pcb) {
#if ASYNC_TCP_SSL_ENABLED
    if(_pcb_secure){
      tcp_ssl_free(_pcb);
    }
#endif
    tcp_arg(_pcb, NULL);
    tcp_sent(_pcb, NULL);
    tcp_recv(_pcb, NULL);
    tcp_err(_pcb, NULL);
    tcp_poll(_pcb, NULL, 0);
    err_t err = tcp_close(_pcb);
    if(err == ERR_OK) {
      _pcb = NULL;
    } else {
      abort();
    }
    if(_discard_cb)
      _discard_cb(_discard_cb_arg, this);
  }
  return;
}

void AsyncClient::_error(err_t err) {
  ASYNC_TCP_DEBUG("_error[%u]:%s err: %s(%d)\n", getConnectionId(), ((NULL == _pcb) ? " NULL == _pcb!," : ""), errorToString(err), err);
  if(_pcb){
#if ASYNC_TCP_SSL_ENABLED
    if(_pcb_secure){
      tcp_ssl_free(_pcb);
    }
#endif
    // At this callback _pcb is possible already freed. Thus, no calls are
    // made to set to NULL other callbacks.
    _pcb = NULL;
  }
  if(_error_cb)
    _error_cb(_error_cb_arg, this, err);
  if(_discard_cb)
    _discard_cb(_discard_cb_arg, this);
}

#if ASYNC_TCP_SSL_ENABLED
void AsyncClient::_ssl_error(err_t err){
  ASYNC_TCP_DEBUG("SSL error (%u)\n", err); // TODO: BR_ERR_... for BearSSL
  if(_error_cb) {
    if(!_handshake_done)
      _error_cb(_error_cb_arg, this, -56);
    _error_cb(_error_cb_arg, this, err);
  }
}

void AsyncClient::setHandshakeTimeout(uint32_t timeout){
  _handshake_timeout = timeout;
}

uint32_t AsyncClient::getHandshakeTimeout(){
  return _handshake_timeout;
}

#endif

void AsyncClient::_sent(std::shared_ptr<ACErrorTracker>& errorTracker, tcp_pcb* pcb, uint16_t len) {
  (void)pcb;
#if ASYNC_TCP_SSL_ENABLED
  if (_pcb_secure && !_handshake_done)
    return;
#endif
  _rx_last_packet = millis();

#if ASYNC_TCP_SSL_ENABLED
  if(_pcb_secure){
#if ASYNC_TCP_SSL_BEARSSL
    int pumped = tcp_ssl_outbuf_pump(pcb);
#endif
    if(!_handshake_done) return;
#if ASYNC_TCP_SSL_BEARSSL
    if(pumped) {
      //_pcb_busy = true;
      _pcb_sent_at = _rx_last_packet;
      _tx_unacked_len+= pumped;
    }
#endif
  }
#endif

  _tx_unacked_len -= len;
  _tx_acked_len += len;
  ASYNC_TCP_DEBUG("_sent[%u]: %4u, unacked=%4u, acked=%4u, space=%4u\n", errorTracker->getConnectionId(), len, _tx_unacked_len, _tx_acked_len, space());
  if(_tx_unacked_len == 0){
    _pcb_busy = false;
    errorTracker->setCloseError(ERR_OK);
    if(_sent_cb) {
      _sent_cb(_sent_cb_arg, this, _tx_acked_len, (millis() - _pcb_sent_at));
      if(!errorTracker->hasClient())
        return;
    }
    _tx_acked_len = 0;
  }
  return;
}

void AsyncClient::_recv(std::shared_ptr<ACErrorTracker>& errorTracker, tcp_pcb* pcb, pbuf* pb, err_t err) {
  // While lwIP v1.4 appears to always call with ERR_OK, 2.x lwIP may present
  // a non-ERR_OK value.
  // https://www.nongnu.org/lwip/2_1_x/tcp_8h.html#a780cfac08b02c66948ab94ea974202e8
  if(NULL == pcb || ERR_OK != err){
    ASYNC_TCP_DEBUG("_recv[%u]:%s err: %s(%d)\n", errorTracker->getConnectionId(), ((NULL == pcb) ? " NULL == pcb!," : ""), errorToString(err), err);
    ASYNC_TCP_ASSERT(ERR_ABRT != err);
    errorTracker->setCloseError(err);
    errorTracker->setErrored(EE_RECV_CB);
    _pcb = pcb;
    if(_pcb)
      clearTcpCallbacks(_pcb);
    _pcb = NULL;
    // I think we are safe from being called from an interrupt context.
    // Best Hint that calling _error() is safe:
    //    https://www.nongnu.org/lwip/2_1_x/group__lwip__nosys.html
    // "Feed incoming packets to netif->input(pbuf, netif) function from
    // mainloop, not from interrupt context. You can allocate a Packet buffers
    // (PBUF) in interrupt context and put them into a queue which is processed
    // from mainloop."
    // And the description of "Mainloop Mode" option 2:
    //    https://www.nongnu.org/lwip/2_1_x/pitfalls.html
    // "2) Run lwIP in a mainloop. ... lwIP is ONLY called from mainloop
    // callstacks here. The ethernet IRQ has to put received telegrams into a
    // queue which is polled in the mainloop. Ensure lwIP is NEVER called from
    // an interrupt, ...!"
    // Based on these comments I am thinking tcp_recv_fn() is called
    // from somebody's mainloop(), which could only have been reached from a
    // delay like function or the Arduino sketch loop() function has returned.
    // What I don't want is for the client sketch to delete the AsyncClient
    // object via _error() while it is in the middle of using it. However,
    // the client sketch must always test that the connection is still up
    // at loop() entry and after the return of any function call, that may
    // have done a delay() or yield().
    _error(err);
    return;
  }

  if(pb == NULL){
    ASYNC_TCP_DEBUG("_recv[%u]: pb == NULL! Closing... %d\n", errorTracker->getConnectionId(), err);
    _close();
    return;
  }
  _rx_last_packet = millis();
  errorTracker->setCloseError(ERR_OK);
#if ASYNC_TCP_SSL_ENABLED
  if(_pcb_secure){
    ASYNC_TCP_DEBUG("_recv[%u]: %d\n", getConnectionId(), pb->tot_len);
    int read_bytes = tcp_ssl_read(pcb, pb);
    if(read_bytes < 0){
      switch (read_bytes) {
        case SSL_CLOSE_NOTIFY:
          // All data processed at TCP layer
          // Report normal read
          break;
#if ASYNC_TCP_SSL_BEARSSL
        case SSL_CANNOT_READ:
          // SSL engine unable to take the data
          // Report out-of-memory
          return;
#endif
        default:
          // Unexpected error, abort connection
          _ssl_error(read_bytes);
          tcp_abort(pcb);
          return;
      }
    }
    return;
  }
#endif
  while(pb != NULL){
    // IF this callback function returns ERR_OK or ERR_ABRT
    // then it is assummed we freed the pbufs.
    // https://www.nongnu.org/lwip/2_1_x/group__tcp__raw.html#ga8afd0b316a87a5eeff4726dc95006ed0
    if(!errorTracker->hasClient()){
      while(pb != NULL){
        pbuf *b = pb;
        pb = b->next;
        b->next = NULL;
        pbuf_free(b);
      }
      return;
    }
    //we should not ack before we assimilate the data
    _ack_pcb = true;
    pbuf *b = pb;
    pb = b->next;
    b->next = NULL;
    ASYNC_TCP_DEBUG("_recv[%u]: %d%s\n", errorTracker->getConnectionId(), b->len, (b->flags&PBUF_FLAG_PUSH)?", PBUF_FLAG_PUSH":"");
    if(_pb_cb){
      _pb_cb(_pb_cb_arg, this, b);
    } else {
      if(_recv_cb){
        _recv_pbuf_flags = b->flags;
        _recv_cb(_recv_cb_arg, this, b->payload, b->len);
      }
      if(errorTracker->hasClient()){
        if(!_ack_pcb)
          _rx_ack_len += b->len;
        else
          tcp_recved(pcb, b->len);
      }
      pbuf_free(b);
    }
  }
  return;
}

void AsyncClient::_poll(std::shared_ptr<ACErrorTracker>& errorTracker, tcp_pcb* pcb){
  (void)pcb;
  errorTracker->setCloseError(ERR_OK);

  // Close requested
  if(_close_pcb){
    ASYNC_TCP_DEBUG("_poll[%u]: Process _close_pcb.\n", errorTracker->getConnectionId() );
    _close_pcb = false;
    _close();
    return;
  }
  uint32_t now = millis();

  // ACK Timeout
  if(_pcb_busy && _ack_timeout) {
    uint32_t time_delta = now - _pcb_sent_at;
    if(time_delta >= _ack_timeout){
      ASYNC_TCP_DEBUG("_poll: ack timeout %d\n", time_delta);
      _pcb_busy = false;
      if(_timeout_cb)
        _timeout_cb(_timeout_cb_arg, this, time_delta);
      return;
    }
  }
  // RX Timeout
  if(_rx_since_timeout) {
    uint32_t time_delta = now - _rx_last_packet;
    if(time_delta >= (_rx_since_timeout * 1000)){
      ASYNC_TCP_DEBUG("_poll: rx timeout %d\n", time_delta);
      if(_timeout_cb)
        _timeout_cb(_timeout_cb_arg, this, time_delta);
      return;
    }
  }
#if ASYNC_TCP_SSL_ENABLED
  // SSL Handshake Timeout
  if(_pcb_secure && !_handshake_done) {
    uint32_t time_delta = now - _rx_last_packet;
    if(time_delta >= _handshake_timeout){
      ASYNC_TCP_DEBUG("_poll: handshake timeout %d\n", time_delta);
      if(_timeout_cb)
        _timeout_cb(_timeout_cb_arg, this, time_delta);
      return;
    }
  }
  if(_pcb_secure){
#if ASYNC_TCP_SSL_BEARSSL
    int pumped = tcp_ssl_outbuf_pump(pcb);
    if(pumped) {
      ASYNC_TCP_DEBUG("_poll: ssl pumped %d\n", pumped);
      if(_handshake_done) {
        _pcb_busy = true;
        _pcb_sent_at = now;
        _tx_unacked_len+= pumped;
      }
      //return ERR_OK;
    }
#endif
  }
#endif
  // Everything is fine
  if(_poll_cb)
    _poll_cb(_poll_cb_arg, this);
  return;
}

#if LWIP_VERSION_MAJOR == 1
void AsyncClient::_dns_found(const char *host, struct ip_addr *ipaddr){
#else
void AsyncClient::_dns_found(const char *host, const ip_addr *ipaddr){
#endif
  if(ipaddr){
#if ASYNC_TCP_SSL_ENABLED
    connect(IPAddress(ipaddr->addr), _connect_port, _pcb_secure, host);
#else
    connect(ipaddr, _connect_port);
#endif
  } else {
    ASYNC_TCP_DEBUG("Error: Name not resolved\n");
    if(_error_cb)
      _error_cb(_error_cb_arg, this, -55);
    if(_discard_cb)
      _discard_cb(_discard_cb_arg, this);
  }
}

// lwIP Callbacks
#if LWIP_VERSION_MAJOR == 1
void AsyncClient::_s_dns_found(const char *host, ip_addr_t *ipaddr, void *arg){
#else
void AsyncClient::_s_dns_found(const char *host, const ip_addr *ipaddr, void *arg){
#endif
  reinterpret_cast<AsyncClient*>(arg)->_dns_found(host, ipaddr);
}

err_t AsyncClient::_s_poll(void *arg, struct tcp_pcb *tpcb) {
  AsyncClient *c = reinterpret_cast<AsyncClient*>(arg);
  std::shared_ptr<ACErrorTracker>errorTracker = c->getACErrorTracker();
  c->_poll(errorTracker, tpcb);
  return errorTracker->getCallbackCloseError();
}

err_t AsyncClient::_s_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *pb, err_t err) {
  AsyncClient *c = reinterpret_cast<AsyncClient*>(arg);
  auto errorTracker = c->getACErrorTracker();
  c->_recv(errorTracker, tpcb, pb, err);
  return errorTracker->getCallbackCloseError();
}

void AsyncClient::_s_error(void *arg, err_t err) {
  AsyncClient *c = reinterpret_cast<AsyncClient*>(arg);
  auto errorTracker = c->getACErrorTracker();
  errorTracker->setCloseError(err);
  errorTracker->setErrored(EE_ERROR_CB);
  c->_error(err);
}

err_t AsyncClient::_s_sent(void *arg, struct tcp_pcb *tpcb, uint16_t len) {
  AsyncClient *c = reinterpret_cast<AsyncClient*>(arg);
  auto errorTracker = c->getACErrorTracker();
  c->_sent(errorTracker, tpcb, len);
  return errorTracker->getCallbackCloseError();
}

err_t AsyncClient::_s_connected(void* arg, void* tpcb, err_t err){
  AsyncClient *c = reinterpret_cast<AsyncClient*>(arg);
  auto errorTracker = c->getACErrorTracker();
  c->_connected(errorTracker, tpcb, err);
  return errorTracker->getCallbackCloseError();
}

#if ASYNC_TCP_SSL_ENABLED
void AsyncClient::_s_data(void *arg, struct tcp_pcb *tcp, uint8_t * data, size_t len){
  (void)tcp;
  AsyncClient *c = reinterpret_cast<AsyncClient*>(arg);
  if(c->_recv_cb)
    c->_recv_cb(c->_recv_cb_arg, c, data, len);
}

void AsyncClient::_s_handshake(void *arg, struct tcp_pcb *tcp, SSL *ssl){
  (void)tcp;
  (void)ssl;
  AsyncClient *c = reinterpret_cast<AsyncClient*>(arg);
  c->_handshake_done = true;
  if(c->_connect_cb)
    c->_connect_cb(c->_connect_cb_arg, c);
}

void AsyncClient::_s_ssl_error(void *arg, struct tcp_pcb *tcp, err_t err){
  reinterpret_cast<AsyncClient*>(arg)->_ssl_error(err);
}
#endif

// Operators

AsyncClient & AsyncClient::operator+=(const AsyncClient &other) {
  if(next == NULL){
    next = (AsyncClient*)(&other);
    next->prev = this;
  } else {
    AsyncClient *c = next;
    while(c->next != NULL) c = c->next;
    c->next =(AsyncClient*)(&other);
    c->next->prev = c;
  }
  return *this;
}

void AsyncClient::setRxTimeout(uint32_t timeout){
  _rx_since_timeout = timeout;
}

uint32_t AsyncClient::getRxTimeout(){
  return _rx_since_timeout;
}

uint32_t AsyncClient::getAckTimeout(){
  return _ack_timeout;
}

void AsyncClient::setAckTimeout(uint32_t timeout){
  _ack_timeout = timeout;
}

void AsyncClient::setNoDelay(bool nodelay){
  if(!_pcb)
    return;
  if(nodelay)
    tcp_nagle_disable(_pcb);
  else
    tcp_nagle_enable(_pcb);
}

bool AsyncClient::getNoDelay(){
  if(!_pcb)
    return false;
  return tcp_nagle_disabled(_pcb);
}

uint16_t AsyncClient::getMss(){
  if(_pcb)
    return tcp_mss(_pcb);
  return 0;
}

uint16_t AsyncClient::getRemotePort() {
  if(!_pcb)
    return 0;
  return _pcb->remote_port;
}


uint16_t AsyncClient::getLocalPort() {
  if(!_pcb)
    return 0;
  return _pcb->local_port;
}

IPAddress AsyncClient::remoteIP() {
  if(!_pcb)
    return IPAddress(0);
  return _pcb->remote_ip;
}

uint16_t AsyncClient::remotePort() {
  return getRemotePort();
}

IPAddress AsyncClient::localIP() {
  if(!_pcb)
    return IPAddress(0);
  return _pcb->local_ip;
}

uint16_t AsyncClient::localPort() {
  return getLocalPort();
}

#if ASYNC_TCP_SSL_ENABLED
SSL * AsyncClient::getSSL(){
  if(_pcb && _pcb_secure){
    return tcp_ssl_get_ssl(_pcb);
  }
  return NULL;
}

#if ASYNC_TCP_SSL_BEARSSL
void AsyncClient::setInBufSize(int size) {
  _ssl_params.iobuf_in_size = size;
}

void AsyncClient::setOutBufSize(int size) {
  _ssl_params.iobuf_out_size = size;
}

void AsyncClient::onSSLCertLookup(AcSSLCertLookupHandler cb, void* arg) {
  _ssl_certlookup_cb = cb;
  _ssl_certlookup_cb_arg = arg;
}

void AsyncClient::setSSLParams(SSL_CTX_PARAMS& params) {
  params.display("setSSLParams orig", Serial);
  _ssl_params = params;
  _ssl_params.display("_ssl_params", Serial);
}

int AsyncClient::_s_certlookup(void *arg, struct tcp_pcb *tcp, void *dn_hash,
  size_t dn_hash_len, uint8_t **buf){
  return reinterpret_cast<AsyncClient*>(arg)->_ssl_certlookup(dn_hash, dn_hash_len, buf);
}

int AsyncClient::_ssl_certlookup(void *dn_hash, size_t dn_hash_len, uint8_t **buf) {
  if (_ssl_certlookup_cb) {
    return _ssl_certlookup_cb(_ssl_certlookup_cb_arg, this, dn_hash, dn_hash_len, buf);
  }
  return 0;
}

#endif

#endif

uint8_t AsyncClient::state() {
  if(!_pcb)
    return 0;
  return _pcb->state;
}

bool AsyncClient::connected(){
  if(!_pcb)
    return false;
#if ASYNC_TCP_SSL_ENABLED
  return _pcb->state == 4 && _handshake_done;
#else
  return _pcb->state == 4;
#endif
}

bool AsyncClient::connecting(){
  if(!_pcb)
    return false;
  return _pcb->state > 0 && _pcb->state < 4;
}

bool AsyncClient::disconnecting(){
  if(!_pcb)
    return false;
  return _pcb->state > 4 && _pcb->state < 10;
}

bool AsyncClient::disconnected(){
  if(!_pcb)
    return true;
  return _pcb->state == 0 || _pcb->state == 10;
}

bool AsyncClient::freeable(){
  if(!_pcb)
    return true;
  return _pcb->state == 0 || _pcb->state > 4;
}

bool AsyncClient::canSend(){
  return !_pcb_busy && (space() > 0);
}


// Callback Setters

void AsyncClient::onConnect(AcConnectHandler cb, void* arg){
  _connect_cb = cb;
  _connect_cb_arg = arg;
}

void AsyncClient::onDisconnect(AcConnectHandler cb, void* arg){
  _discard_cb = cb;
  _discard_cb_arg = arg;
}

void AsyncClient::onAck(AcAckHandler cb, void* arg){
  _sent_cb = cb;
  _sent_cb_arg = arg;
}

void AsyncClient::onError(AcErrorHandler cb, void* arg){
  _error_cb = cb;
  _error_cb_arg = arg;
}

void AsyncClient::onData(AcDataHandler cb, void* arg){
  _recv_cb = cb;
  _recv_cb_arg = arg;
}

void AsyncClient::onPacket(AcPacketHandler cb, void* arg){
  _pb_cb = cb;
  _pb_cb_arg = arg;
}

void AsyncClient::onTimeout(AcTimeoutHandler cb, void* arg){
  _timeout_cb = cb;
  _timeout_cb_arg = arg;
}

void AsyncClient::onPoll(AcConnectHandler cb, void* arg){
  _poll_cb = cb;
  _poll_cb_arg = arg;
}


size_t AsyncClient::space(){
#if ASYNC_TCP_SSL_ENABLED
  if((_pcb != NULL) && (_pcb->state == 4) && _handshake_done){
    uint16_t s = tcp_sndbuf(_pcb);
    if(_pcb_secure){
#ifdef AXTLS_2_0_0_SNDBUF
      return tcp_ssl_sndbuf(_pcb);
#else
      if(s >= 128) //safe approach
        return s - 128;
      return 0;
#endif
    }
    return s;
  }
#else // ASYNC_TCP_SSL_ENABLED
  if((_pcb != NULL) && (_pcb->state == 4)){
    return tcp_sndbuf(_pcb);
  }
#endif // ASYNC_TCP_SSL_ENABLED
  return 0;
}

void AsyncClient::ackPacket(struct pbuf * pb){
  if(!pb){
    return;
  }
  tcp_recved(_pcb, pb->len);
  pbuf_free(pb);
}

PGM_P AsyncClient::errorToString(int8_t error) {
  switch (error) {
    case ERR_OK:         return "No error, everything OK";
    case ERR_MEM:        return "Out of memory error";
    case ERR_BUF:        return "Buffer error";
    case ERR_TIMEOUT:    return "Timeout";
    case ERR_RTE:        return "Routing problem";
    case ERR_INPROGRESS: return "Operation in progress";
    case ERR_VAL:        return "Illegal value";
    case ERR_WOULDBLOCK: return "Operation would block";
    case ERR_ABRT:       return "Connection aborted";
    case ERR_RST:        return "Connection reset";
    case ERR_CLSD:       return "Connection closed";
    case ERR_CONN:       return "Not connected";
    case ERR_ARG:        return "Illegal argument";
    case ERR_USE:        return "Address in use";
#if defined(LWIP_VERSION_MAJOR) && (LWIP_VERSION_MAJOR > 1)
    case ERR_ALREADY:    return "Already connectioning";
#endif
    case ERR_IF:         return "Low-level netif error";
    case ERR_ISCONN:     return "Connection already established";
    case -55:            return "DNS failed";
    default:             return "Unknown error";
  }
}

PGM_P AsyncClient::stateToString(){
  switch(state()){
    case tcp_state::CLOSED: return PSTR("Closed");
    case tcp_state::LISTEN: return PSTR("Listen");
    case tcp_state::SYN_SENT: return PSTR("SYN Sent");
    case tcp_state::SYN_RCVD: return PSTR("SYN Received");
    case tcp_state::ESTABLISHED: return PSTR("Established");
    case tcp_state::FIN_WAIT_1: return PSTR("FIN Wait 1");
    case tcp_state::FIN_WAIT_2: return PSTR("FIN Wait 2");
    case tcp_state::CLOSE_WAIT: return PSTR("Close Wait");
    case tcp_state::CLOSING: return PSTR("Closing");
    case tcp_state::LAST_ACK: return PSTR("Last ACK");
    case tcp_state::TIME_WAIT: return PSTR("Time Wait");
    default: return PSTR("UNKNOWN");
  }
}

/*
  Async TCP Server
*/
struct pending_pcb {
    tcp_pcb* pcb;
    pbuf *pb;
    struct pending_pcb * next;
};

AsyncServer::AsyncServer(IPAddress addr, uint16_t port)
  : _port(port)
  , _addr(addr)
  , _noDelay(false)
  , _pcb(0)
  , _connect_cb(0)
  , _connect_cb_arg(0)
#if ASYNC_TCP_SSL_ENABLED
  , _pending(NULL)
  , _ssl_ctx(NULL)
#if ASYNC_TCP_SSL_AXTLS
  , _file_cb(0)
  , _file_cb_arg(0)
#endif
#endif
{}

AsyncServer::AsyncServer(uint16_t port)
  : _port(port)
  , _addr(IP_ANY_TYPE)
  , _noDelay(false)
  , _pcb(0)
  , _connect_cb(0)
  , _connect_cb_arg(0)
#if ASYNC_TCP_SSL_ENABLED
  , _pending(NULL)
  , _ssl_ctx(NULL)
#if ASYNC_TCP_SSL_AXTLS
  , _file_cb(0)
  , _file_cb_arg(0)
#endif
#endif
{}

AsyncServer::~AsyncServer(){
  end();
}

void AsyncServer::onClient(AcConnectHandler cb, void* arg){
  _connect_cb = cb;
  _connect_cb_arg = arg;
}

#if ASYNC_TCP_SSL_ENABLED
#if ASYNC_TCP_SSL_AXTLS
void AsyncServer::beginSecure(const char *cert, const char *key, const char *password){
  if(_ssl_ctx){
    return;
  }
  tcp_ssl_file(_s_cert, this);
  _ssl_ctx = tcp_ssl_new_server_ctx(cert, key, password);
  if(_ssl_ctx){
    begin();
  }
}

void AsyncServer::onSslFileRequest(AcSSlFileHandler cb, void* arg){
  _file_cb = cb;
  _file_cb_arg = arg;
}
int AsyncServer::_cert(const char *filename, uint8_t **buf){
  if(_file_cb){
    return _file_cb(_file_cb_arg, filename, buf);
  }
  *buf = 0;
  return 0;
}

int AsyncServer::_s_cert(void *arg, const char *filename, uint8_t **buf){
  return reinterpret_cast<AsyncServer*>(arg)->_cert(filename, buf);
}
#endif
#endif

void AsyncServer::begin(){
  if(_pcb)
    return;

  int8_t err;
  tcp_pcb* pcb = tcp_new();
  if(!pcb){
    return;
  }

  ip_addr_t local_addr;
  local_addr.addr = (uint32_t) _addr;
  err = tcp_bind(pcb, &local_addr, _port);

  if(err != ERR_OK) {
    tcp_close(pcb);
    return;
  }

  tcp_pcb* listen_pcb = tcp_listen(pcb);
  if(!listen_pcb) {
    tcp_close(pcb);
    return;
  }
  _pcb = listen_pcb;
  tcp_arg(_pcb, (void*) this);
  tcp_accept(_pcb, &_s_accept);
}

void AsyncServer::end(){
  if(_pcb){
    //cleanup all connections?
    tcp_arg(_pcb, NULL);
    tcp_accept(_pcb, NULL);
    if(tcp_close(_pcb) != ERR_OK){
      tcp_abort(_pcb);
    }
    _pcb = NULL;
  }
#if ASYNC_TCP_SSL_ENABLED
  if(_ssl_ctx){
    tcp_ssl_ctx_free(_ssl_ctx);
    _ssl_ctx = NULL;
    if(_pending){
      struct pending_pcb * p;
      while(_pending){
        p = _pending;
        _pending = _pending->next;
        if(p->pb){
          pbuf_free(p->pb);
        }
        free(p);
      }
    }
  }
#endif
}

void AsyncServer::setNoDelay(bool nodelay){
  _noDelay = nodelay;
}

bool AsyncServer::getNoDelay(){
  return _noDelay;
}

uint8_t AsyncServer::status(){
  if(!_pcb)
    return 0;
  return _pcb->state;
}

err_t AsyncServer::_accept(tcp_pcb* pcb, err_t err){
  //http://savannah.nongnu.org/bugs/?43739
  if(NULL == pcb || ERR_OK != err){
    // https://www.nongnu.org/lwip/2_1_x/tcp_8h.html#a00517abce6856d6c82f0efebdafb734d
    // An error code if there has been an error accepting. Only return ERR_ABRT
    // if you have called tcp_abort from within the callback function!
    // eg. 2.1.0 could call with error on failure to allocate pcb.
    ASYNC_TCP_DEBUG("_accept:%s err: %d\n", ((NULL == pcb) ? " NULL == pcb!," : ""), err);
    ASYNC_TCP_ASSERT(ERR_ABRT != err);
#ifdef DEBUG_MORE
    incEventCount(EE_ACCEPT_CB);
#endif
    return ERR_OK;
  }

  if(_connect_cb){
#if ASYNC_TCP_SSL_ENABLED
    if(_noDelay || _ssl_ctx)
#else
    if(_noDelay)
#endif
      tcp_nagle_disable(pcb);
    else
      tcp_nagle_enable(pcb);

    AsyncClient *c;
#if ASYNC_TCP_SSL_ENABLED
    if(_ssl_ctx){
      if(tcp_ssl_has_client() || _pending){
        struct pending_pcb * new_item = (struct pending_pcb*)malloc(sizeof(struct pending_pcb));
        if(!new_item){
          ASYNC_TCP_DEBUG("### malloc new pending failed!\n");
          if(tcp_close(pcb) != ERR_OK){
            tcp_abort(pcb);
            return ERR_ABRT;
          }
          return ERR_OK;
        }
        //ASYNC_TCP_DEBUG("### put to wait: %d\n", _clients_waiting);
        new_item->pcb = pcb;
        new_item->pb = NULL;
        new_item->next = NULL;
        tcp_setprio(_pcb, TCP_PRIO_MIN);
        tcp_arg(pcb, this);
        tcp_poll(pcb, &_s_poll, 1);
        tcp_recv(pcb, &_s_recv);

        if(_pending == NULL){
          _pending = new_item;
        } else {
          struct pending_pcb * p = _pending;
          while(p->next != NULL)
            p = p->next;
          p->next = new_item;
        }
      } else {
        c = new AsyncClient(pcb, _ssl_ctx);
        if(c){
          ASYNC_TCP_DEBUG("_accept[%u]: SSL connected\n", c->getConnectionId());
          c->onConnect([this](void * arg, AsyncClient *c){
            (void)arg;
            _connect_cb(_connect_cb_arg, c);
          }, this);
        } else {
          ASYNC_TCP_DEBUG("_accept[_ssl_ctx]: new AsyncClient() failed, connection aborted!\n");
          if(tcp_close(pcb) != ERR_OK){
            tcp_abort(pcb);
            return ERR_ABRT;
          }
        }
      }
      return ERR_OK;
    } else {
      c = new AsyncClient(pcb, NULL);
    }
#else
    c = new AsyncClient(pcb);
#endif
    if(c){
      _connect_cb(_connect_cb_arg, c);
      return ERR_OK;
    }
  }
  if(tcp_close(pcb) != ERR_OK){
    tcp_abort(pcb);
    return ERR_ABRT;
  }
  return ERR_OK;
}

err_t AsyncServer::_s_accept(void *arg, tcp_pcb* pcb, err_t err){
  return reinterpret_cast<AsyncServer*>(arg)->_accept(pcb, err);
}

#if ASYNC_TCP_SSL_ENABLED
err_t AsyncServer::_poll(tcp_pcb* pcb){
  err_t err = ERR_OK;
  if(!tcp_ssl_has_client() && _pending){
    struct pending_pcb * p = _pending;
    if(p->pcb == pcb){
      _pending = _pending->next;
    } else {
      while(p->next && p->next->pcb != pcb) p = p->next;
      if(!p->next) return ERR_OK;
      struct pending_pcb * b = p->next;
      p->next = b->next;
      p = b;
    }
    //ASYNC_TCP_DEBUG("### remove from wait: %d\n", _clients_waiting);
    AsyncClient *c = new AsyncClient(pcb, _ssl_ctx);
    if(c){
      c->onConnect([this](void * arg, AsyncClient *c){
        (void)arg;
        _connect_cb(_connect_cb_arg, c);
      }, this);
      if(p->pb) {
        auto errorTracker = c->getACErrorTracker();
        c->_recv(errorTracker, pcb, p->pb, 0);
        err = errorTracker->getCallbackCloseError();
      }
    }
    // Should there be error handling for when "new AsynClient" fails??
    free(p);
  }
  return err;
}

err_t AsyncServer::_recv(struct tcp_pcb *pcb, struct pbuf *pb, err_t err){
  (void)err;
  if(!_pending)
    return ERR_OK;

  struct pending_pcb * p;

  if(!pb){
    //ASYNC_TCP_DEBUG("### close from wait: %d\n", _clients_waiting);
    p = _pending;
    if(p->pcb == pcb){
      _pending = _pending->next;
    } else {
      while(p->next && p->next->pcb != pcb) p = p->next;
      if(!p->next) return 0;
      struct pending_pcb * b = p->next;
      p->next = b->next;
      p = b;
    }
    if(p->pb){
      pbuf_free(p->pb);
    }
    free(p);
    size_t err = tcp_close(pcb);
    if (err != ERR_OK) {
      tcp_abort(pcb);
      return ERR_ABRT;
    }
  } else {
    //ASYNC_TCP_DEBUG("### wait _recv: %u %d\n", pb->tot_len, _clients_waiting);
    p = _pending;
    while(p && p->pcb != pcb)
      p = p->next;
    if(p){
      if(p->pb){
        pbuf_chain(p->pb, pb);
      } else {
        p->pb = pb;
      }
    }
  }
  return ERR_OK;
}

err_t AsyncServer::_s_poll(void *arg, struct tcp_pcb *pcb){
  return reinterpret_cast<AsyncServer*>(arg)->_poll(pcb);
}

err_t AsyncServer::_s_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *pb, err_t err){
  return reinterpret_cast<AsyncServer*>(arg)->_recv(pcb, pb, err);
}
#endif
