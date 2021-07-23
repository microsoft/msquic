#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_LOOKUP_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "lookup.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_LOOKUP_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_LOOKUP_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "lookup.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_5_ARGS_TRACE_LookupCidFound



/*----------------------------------------------------------
// Decoder Ring for LookupCidFound
// [look][%p] Lookup Hash=%u found %p
// QuicTraceLogVerbose(
            LookupCidFound,
            "[look][%p] Lookup Hash=%u found %p",
            Lookup,
            Hash,
            Connection);
// arg2 = arg2 = Lookup
// arg3 = arg3 = Hash
// arg4 = arg4 = Connection
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_LookupCidFound(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_LOOKUP_C, LookupCidFound , arg2, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_LookupCidNotFound



/*----------------------------------------------------------
// Decoder Ring for LookupCidNotFound
// [look][%p] Lookup Hash=%u not found
// QuicTraceLogVerbose(
            LookupCidNotFound,
            "[look][%p] Lookup Hash=%u not found",
            Lookup,
            Hash);
// arg2 = arg2 = Lookup
// arg3 = arg3 = Hash
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LookupCidNotFound(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LOOKUP_C, LookupCidNotFound , arg2, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_LookupRemoteHashFound



/*----------------------------------------------------------
// Decoder Ring for LookupRemoteHashFound
// [look][%p] Lookup RemoteHash=%u found %p
// QuicTraceLogVerbose(
                LookupRemoteHashFound,
                "[look][%p] Lookup RemoteHash=%u found %p",
                Lookup,
                Hash,
                Entry->Connection);
// arg2 = arg2 = Lookup
// arg3 = arg3 = Hash
// arg4 = arg4 = Entry->Connection
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_LookupRemoteHashFound(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_LOOKUP_C, LookupRemoteHashFound , arg2, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_LookupRemoteHashNotFound



/*----------------------------------------------------------
// Decoder Ring for LookupRemoteHashNotFound
// [look][%p] Lookup RemoteHash=%u not found
// QuicTraceLogVerbose(
        LookupRemoteHashNotFound,
        "[look][%p] Lookup RemoteHash=%u not found",
        Lookup,
        Hash);
// arg2 = arg2 = Lookup
// arg3 = arg3 = Hash
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LookupRemoteHashNotFound(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LOOKUP_C, LookupRemoteHashNotFound , arg2, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_LookupCidInsert



/*----------------------------------------------------------
// Decoder Ring for LookupCidInsert
// [look][%p] Insert Conn=%p Hash=%u
// QuicTraceLogVerbose(
        LookupCidInsert,
        "[look][%p] Insert Conn=%p Hash=%u",
        Lookup,
        SourceCid->Connection,
        Hash);
// arg2 = arg2 = Lookup
// arg3 = arg3 = SourceCid->Connection
// arg4 = arg4 = Hash
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_LookupCidInsert(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_LOOKUP_C, LookupCidInsert , arg2, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_LookupRemoteHashInsert



/*----------------------------------------------------------
// Decoder Ring for LookupRemoteHashInsert
// [look][%p] Insert Conn=%p RemoteHash=%u
// QuicTraceLogVerbose(
        LookupRemoteHashInsert,
        "[look][%p] Insert Conn=%p RemoteHash=%u",
        Lookup,
        Connection,
        Hash);
// arg2 = arg2 = Lookup
// arg3 = arg3 = Connection
// arg4 = arg4 = Hash
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_LookupRemoteHashInsert(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_LOOKUP_C, LookupRemoteHashInsert , arg2, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_LookupCidRemoved



/*----------------------------------------------------------
// Decoder Ring for LookupCidRemoved
// [look][%p] Remove Conn=%p
// QuicTraceLogVerbose(
        LookupCidRemoved,
        "[look][%p] Remove Conn=%p",
        Lookup,
        SourceCid->Connection);
// arg2 = arg2 = Lookup
// arg3 = arg3 = SourceCid->Connection
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LookupCidRemoved(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LOOKUP_C, LookupCidRemoved , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_lookup.c.clog.h.c"
#endif

