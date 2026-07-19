#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_PATHID_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "pathid.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_PATHID_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_PATHID_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "pathid.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogConnWarning
#define _clog_MACRO_QuicTraceLogConnWarning  1
#define QuicTraceLogConnWarning(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogConnVerbose
#define _clog_MACRO_QuicTraceLogConnVerbose  1
#define QuicTraceLogConnVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for NoReplacementCidForRetire
// [conn][%p] Can't retire current CID because we don't have a replacement
// QuicTraceLogConnWarning(
            NoReplacementCidForRetire,
            PathID->Connection,
            "Can't retire current CID because we don't have a replacement");
// arg1 = arg1 = PathID->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_NoReplacementCidForRetire
#define _clog_3_ARGS_TRACE_NoReplacementCidForRetire(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_PATHID_C, NoReplacementCidForRetire , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for NonActivePathCidRetired
// [conn][%p] Non-active path has no replacement for retired CID.
// QuicTraceLogConnWarning(
                NonActivePathCidRetired,
                PathID->Connection,
                "Non-active path has no replacement for retired CID.");
// arg1 = arg1 = PathID->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_NonActivePathCidRetired
#define _clog_3_ARGS_TRACE_NonActivePathCidRetired(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_PATHID_C, NonActivePathCidRetired , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for NewSrcCidNameCollision
// [conn][%p] CID collision, trying again
// QuicTraceLogConnVerbose(
                NewSrcCidNameCollision,
                PathID->Connection,
                "CID collision, trying again");
// arg1 = arg1 = PathID->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_NewSrcCidNameCollision
#define _clog_3_ARGS_TRACE_NewSrcCidNameCollision(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_PATHID_C, NewSrcCidNameCollision , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ZeroLengthCidRetire
// [conn][%p] Can't retire current CID because it's zero length
// QuicTraceLogConnVerbose(
            ZeroLengthCidRetire,
            PathID->Connection,
            "Can't retire current CID because it's zero length");
// arg1 = arg1 = PathID->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ZeroLengthCidRetire
#define _clog_3_ARGS_TRACE_ZeroLengthCidRetire(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_PATHID_C, ZeroLengthCidRetire , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPathIDCloseTimerExpired
// [conn][%p][pathid][%u] Close Timer expired
// QuicTraceEvent(
                ConnPathIDCloseTimerExpired,
                "[conn][%p][pathid][%u] Close Timer expired",
                PathID->Connection,
                PathID->ID);
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnPathIDCloseTimerExpired
#define _clog_4_ARGS_TRACE_ConnPathIDCloseTimerExpired(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PATHID_C, ConnPathIDCloseTimerExpired , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnDestCidAdded
// [conn][%p][pathid][%u] (SeqNum=%llu) New Destination CID: %!CID!
// QuicTraceEvent(
        ConnDestCidAdded,
        "[conn][%p][pathid][%u] (SeqNum=%llu) New Destination CID: %!CID!",
        PathID->Connection,
        PathID->ID,
        DestCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = DestCid->CID.SequenceNumber = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data) = arg5
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_ConnDestCidAdded
#define _clog_7_ARGS_TRACE_ConnDestCidAdded(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg5_len)\
tracepoint(CLOG_PATHID_C, ConnDestCidAdded , arg2, arg3, arg4, arg5_len, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnSourceCidAdded
// [conn][%p][pathid][%u] (SeqNum=%llu) New Source CID: %!CID!
// QuicTraceEvent(
        ConnSourceCidAdded,
        "[conn][%p][pathid][%u] (SeqNum=%llu) New Source CID: %!CID!",
        PathID->Connection,
        PathID->ID,
        SourceCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = SourceCid->CID.SequenceNumber = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data) = arg5
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_ConnSourceCidAdded
#define _clog_7_ARGS_TRACE_ConnSourceCidAdded(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg5_len)\
tracepoint(CLOG_PATHID_C, ConnSourceCidAdded , arg2, arg3, arg4, arg5_len, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "new Src CID",
                sizeof(QUIC_CID_SLIST_ENTRY) + MsQuicLib.CidTotalLength);
// arg2 = arg2 = "new Src CID" = arg2
// arg3 = arg3 = sizeof(QUIC_CID_SLIST_ENTRY) + MsQuicLib.CidTotalLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PATHID_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    PathID->Connection,
                    "Too many CID collisions");
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = "Too many CID collisions" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnError
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PATHID_C, ConnError , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnDestCidRemoved
// [conn][%p][pathid][%u] (SeqNum=%llu) Removed Destination CID: %!CID!
// QuicTraceEvent(
        ConnDestCidRemoved,
        "[conn][%p][pathid][%u] (SeqNum=%llu) Removed Destination CID: %!CID!",
        PathID->Connection,
        PathID->ID,
        DestCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = DestCid->CID.SequenceNumber = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data) = arg5
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_ConnDestCidRemoved
#define _clog_7_ARGS_TRACE_ConnDestCidRemoved(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg5_len)\
tracepoint(CLOG_PATHID_C, ConnDestCidRemoved , arg2, arg3, arg4, arg5_len, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnDestCidUpdated
// [conn][%p][pathid][%u] (SeqNum=%llu) Updated Destination CID: %!CID!
// QuicTraceEvent(
        ConnDestCidUpdated,
        "[conn][%p][pathid][%u] (SeqNum=%llu) Updated Destination CID: %!CID!",
        PathID->Connection,
        PathID->ID,
        Path->DestCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(Path->DestCid->CID.Length, Path->DestCid->CID.Data));
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = Path->DestCid->CID.SequenceNumber = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(Path->DestCid->CID.Length, Path->DestCid->CID.Data) = arg5
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_ConnDestCidUpdated
#define _clog_7_ARGS_TRACE_ConnDestCidUpdated(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg5_len)\
tracepoint(CLOG_PATHID_C, ConnDestCidUpdated , arg2, arg3, arg4, arg5_len, arg5);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_pathid.c.clog.h.c"
#endif
