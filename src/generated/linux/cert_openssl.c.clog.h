#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_CERT_OPENSSL_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "cert_openssl.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_CERT_OPENSSL_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_CERT_OPENSSL_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "cert_openssl.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_4_ARGS_TRACE_CertOpenSslGetProcessAddressFailure



/*----------------------------------------------------------
// Decoder Ring for CertOpenSslGetProcessAddressFailure
// [cert] GetProcAddress failed for %s, 0x%x
// QuicTraceLogVerbose(
        CertOpenSslGetProcessAddressFailure,
        "[cert] GetProcAddress failed for %s, 0x%x",
        FuncName,
        Error);
// arg2 = arg2 = FuncName
// arg3 = arg3 = Error
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_CertOpenSslGetProcessAddressFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CERT_OPENSSL_C, CertOpenSslGetProcessAddressFailure , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Failed to Load libmipki.dll");
// arg2 = arg2 = Status
// arg3 = arg3 = "Failed to Load libmipki.dll"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CERT_OPENSSL_C, LibraryErrorStatus , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            erridx,
            "mipki_init failed");
// arg2 = arg2 = erridx
// arg3 = arg3 = "mipki_init failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "mipki_add_root_file_or_path failed");
// arg2 = arg2 = "mipki_add_root_file_or_path failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CERT_OPENSSL_C, LibraryError , arg2);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_cert_openssl.c.clog.h.c"
#endif
