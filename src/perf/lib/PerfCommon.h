/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Common definitions.

--*/


#pragma once

#define PERF_ALPN                           "perf"
#define PERF_DEFAULT_PORT                   4433
#define PERF_DEFAULT_DISCONNECT_TIMEOUT     (10 * 1000)
#define PERF_DEFAULT_IDLE_TIMEOUT           (30 * 1000)
#define PERF_DEFAULT_CONN_FLOW_CONTROL      0x8000000
#define PERF_DEFAULT_STREAM_COUNT           10000
#define PERF_MAX_THREAD_COUNT               128

#define PERF_DEFAULT_SEND_BUFFER_SIZE       0x20000
#define PERF_DEFAULT_IO_SIZE                0x10000

#define TPUT_DEFAULT_IDLE_TIMEOUT           (1 * 1000)

#define RPS_MAX_CLIENT_PORT_COUNT           256
#define RPS_MAX_REQUESTS_PER_SECOND         2000000 // 1.5 million RPS max as a guess
#define RPS_DEFAULT_RUN_TIME                (10 * 1000)
#define RPS_DEFAULT_CONNECTION_COUNT        1000
#define RPS_DEFAULT_REQUEST_LENGTH          0
#define RPS_DEFAULT_RESPONSE_LENGTH         0
#define RPS_ALL_CONNECT_TIMEOUT             10000
#define RPS_IDLE_WAIT                       2000

#define HPS_DEFAULT_RUN_TIME                (10 * 1000)
#define HPS_DEFAULT_IDLE_TIMEOUT            (5 * 1000)
#define HPS_DEFAULT_PARALLEL_COUNT          100
#define HPS_BINDINGS_PER_WORKER             10
