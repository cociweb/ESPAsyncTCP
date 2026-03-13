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

#ifndef TCP_MSS
// May have been definded as a -DTCP_MSS option on the compile line or not.
// Arduino core 2.3.0 or earlier does not do the -DTCP_MSS option.
// Later versions may set this option with info from board.txt.
// However, Core 2.4.0 and up board.txt does not define TCP_MSS for lwIP v1.4
#define TCP_MSS (1460)
#endif

#define ASYNC_TCP_DEBUG_DO(X) X
#define TCP_SSL_DEBUG_DO(X) X

// Force rebuild - updated timestamp
#define ASYNC_TCP_DEBUG(...) ASYNC_TCP_DEBUG_DO(Serial.printf(__VA_ARGS__))
#define TCP_SSL_DEBUG(...) TCP_SSL_DEBUG_DO(ets_printf(__VA_ARGS__))

#endif /* LIBRARIES_ESPASYNCTCP_SRC_ASYNC_CONFIG_H_ */
