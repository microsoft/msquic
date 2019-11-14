/*++

  Copyright (c) Microsoft Corporation.
  Licensed under the MIT License.

--*/

typedef enum {
    SpinQuicAPICallCreateConnection = 0,
    SpinQuicAPICallStartConnection,
    SpinQuicAPICallShutdownConnection,
    SpinQuicAPICallCloseConnection,
    SpinQuicAPICallStreamOpen,
    SpinQuicAPICallStreamStart,
    SpinQuicAPICallStreamSend,
    SpinQuicAPICallStreamShutdown,
    SpinQuicAPICallStreamClose,
    SpinQuicAPICallSetParamSession,
    SpinQuicAPICallSetParamConnection,
    SpinQuicAPICallCount, // Always the last element
} SpinQuicAPICall;

#define SQ_ASSERT(x) do { \
    int __tmp_ret = (x); \
    if (!__tmp_ret) { \
       printf("%s:%d %s != TRUE", __FILE__, __LINE__, #x); \
       exit(10); \
    } \
} while (0);
