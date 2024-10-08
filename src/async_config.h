#ifndef LIBRARIES_ESPASYNCTCP_SRC_ASYNC_CONFIG_H_
#define LIBRARIES_ESPASYNCTCP_SRC_ASYNC_CONFIG_H_

#ifndef ASYNC_TCP_SSL_ENABLED
#define ASYNC_TCP_SSL_ENABLED 0
#endif

#ifndef ASYNC_TCP_SSL_BEARSSL
#define ASYNC_TCP_SSL_BEARSSL 1
#endif

#ifndef ASYNC_TCP_SSL_AXTLS
#define ASYNC_TCP_SSL_AXTLS 0
#endif

#define ASYNC_TCP_DEBUG_DO(X) X
#define TCP_SSL_DEBUG_DO(X) X

#define ASYNC_TCP_DEBUG(...) ASYNC_TCP_DEBUG_DO(Serial.printf(__VA_ARGS__))
#define TCP_SSL_DEBUG(...) TCP_SSL_DEBUG_DO(ets_printf(__VA_ARGS__))

#endif /* LIBRARIES_ESPASYNCTCP_SRC_ASYNC_CONFIG_H_ */
