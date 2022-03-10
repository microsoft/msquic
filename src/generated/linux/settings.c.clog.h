#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_SETTINGS_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "settings.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_SETTINGS_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_SETTINGS_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "settings.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogError
#define _clog_MACRO_QuicTraceLogError  1
#define QuicTraceLogError(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for SettingDumpSendBufferingEnabled
// [sett] SendBufferingEnabled   = %hhu
// QuicTraceLogVerbose(SettingDumpSendBufferingEnabled,    "[sett] SendBufferingEnabled   = %hhu", Settings->SendBufferingEnabled);
// arg2 = arg2 = Settings->SendBufferingEnabled = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpSendBufferingEnabled
#define _clog_3_ARGS_TRACE_SettingDumpSendBufferingEnabled(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpSendBufferingEnabled , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpPacingEnabled
// [sett] PacingEnabled          = %hhu
// QuicTraceLogVerbose(SettingDumpPacingEnabled,           "[sett] PacingEnabled          = %hhu", Settings->PacingEnabled);
// arg2 = arg2 = Settings->PacingEnabled = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpPacingEnabled
#define _clog_3_ARGS_TRACE_SettingDumpPacingEnabled(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpPacingEnabled , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpMigrationEnabled
// [sett] MigrationEnabled       = %hhu
// QuicTraceLogVerbose(SettingDumpMigrationEnabled,        "[sett] MigrationEnabled       = %hhu", Settings->MigrationEnabled);
// arg2 = arg2 = Settings->MigrationEnabled = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpMigrationEnabled
#define _clog_3_ARGS_TRACE_SettingDumpMigrationEnabled(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMigrationEnabled , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpDatagramReceiveEnabled
// [sett] DatagramReceiveEnabled = %hhu
// QuicTraceLogVerbose(SettingDumpDatagramReceiveEnabled,  "[sett] DatagramReceiveEnabled = %hhu", Settings->DatagramReceiveEnabled);
// arg2 = arg2 = Settings->DatagramReceiveEnabled = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpDatagramReceiveEnabled
#define _clog_3_ARGS_TRACE_SettingDumpDatagramReceiveEnabled(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpDatagramReceiveEnabled , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxOperationsPerDrain
// [sett] MaxOperationsPerDrain  = %hhu
// QuicTraceLogVerbose(SettingDumpMaxOperationsPerDrain,   "[sett] MaxOperationsPerDrain  = %hhu", Settings->MaxOperationsPerDrain);
// arg2 = arg2 = Settings->MaxOperationsPerDrain = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpMaxOperationsPerDrain
#define _clog_3_ARGS_TRACE_SettingDumpMaxOperationsPerDrain(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMaxOperationsPerDrain , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpRetryMemoryLimit
// [sett] RetryMemoryLimit       = %hu
// QuicTraceLogVerbose(SettingDumpRetryMemoryLimit,        "[sett] RetryMemoryLimit       = %hu", Settings->RetryMemoryLimit);
// arg2 = arg2 = Settings->RetryMemoryLimit = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpRetryMemoryLimit
#define _clog_3_ARGS_TRACE_SettingDumpRetryMemoryLimit(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpRetryMemoryLimit , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpLoadBalancingMode
// [sett] LoadBalancingMode      = %hu
// QuicTraceLogVerbose(SettingDumpLoadBalancingMode,       "[sett] LoadBalancingMode      = %hu", Settings->LoadBalancingMode);
// arg2 = arg2 = Settings->LoadBalancingMode = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpLoadBalancingMode
#define _clog_3_ARGS_TRACE_SettingDumpLoadBalancingMode(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpLoadBalancingMode , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxStatelessOperations
// [sett] MaxStatelessOperations = %u
// QuicTraceLogVerbose(SettingDumpMaxStatelessOperations,  "[sett] MaxStatelessOperations = %u", Settings->MaxStatelessOperations);
// arg2 = arg2 = Settings->MaxStatelessOperations = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpMaxStatelessOperations
#define _clog_3_ARGS_TRACE_SettingDumpMaxStatelessOperations(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMaxStatelessOperations , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxWorkerQueueDelayUs
// [sett] MaxWorkerQueueDelayUs  = %u
// QuicTraceLogVerbose(SettingDumpMaxWorkerQueueDelayUs,   "[sett] MaxWorkerQueueDelayUs  = %u", Settings->MaxWorkerQueueDelayUs);
// arg2 = arg2 = Settings->MaxWorkerQueueDelayUs = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpMaxWorkerQueueDelayUs
#define _clog_3_ARGS_TRACE_SettingDumpMaxWorkerQueueDelayUs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMaxWorkerQueueDelayUs , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpInitialWindowPackets
// [sett] InitialWindowPackets   = %u
// QuicTraceLogVerbose(SettingDumpInitialWindowPackets,    "[sett] InitialWindowPackets   = %u", Settings->InitialWindowPackets);
// arg2 = arg2 = Settings->InitialWindowPackets = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpInitialWindowPackets
#define _clog_3_ARGS_TRACE_SettingDumpInitialWindowPackets(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpInitialWindowPackets , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpSendIdleTimeoutMs
// [sett] SendIdleTimeoutMs      = %u
// QuicTraceLogVerbose(SettingDumpSendIdleTimeoutMs,       "[sett] SendIdleTimeoutMs      = %u", Settings->SendIdleTimeoutMs);
// arg2 = arg2 = Settings->SendIdleTimeoutMs = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpSendIdleTimeoutMs
#define _clog_3_ARGS_TRACE_SettingDumpSendIdleTimeoutMs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpSendIdleTimeoutMs , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpInitialRttMs
// [sett] InitialRttMs           = %u
// QuicTraceLogVerbose(SettingDumpInitialRttMs,            "[sett] InitialRttMs           = %u", Settings->InitialRttMs);
// arg2 = arg2 = Settings->InitialRttMs = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpInitialRttMs
#define _clog_3_ARGS_TRACE_SettingDumpInitialRttMs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpInitialRttMs , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxAckDelayMs
// [sett] MaxAckDelayMs          = %u
// QuicTraceLogVerbose(SettingDumpMaxAckDelayMs,           "[sett] MaxAckDelayMs          = %u", Settings->MaxAckDelayMs);
// arg2 = arg2 = Settings->MaxAckDelayMs = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpMaxAckDelayMs
#define _clog_3_ARGS_TRACE_SettingDumpMaxAckDelayMs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMaxAckDelayMs , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpDisconnectTimeoutMs
// [sett] DisconnectTimeoutMs    = %u
// QuicTraceLogVerbose(SettingDumpDisconnectTimeoutMs,     "[sett] DisconnectTimeoutMs    = %u", Settings->DisconnectTimeoutMs);
// arg2 = arg2 = Settings->DisconnectTimeoutMs = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpDisconnectTimeoutMs
#define _clog_3_ARGS_TRACE_SettingDumpDisconnectTimeoutMs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpDisconnectTimeoutMs , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpKeepAliveIntervalMs
// [sett] KeepAliveIntervalMs    = %u
// QuicTraceLogVerbose(SettingDumpKeepAliveIntervalMs,     "[sett] KeepAliveIntervalMs    = %u", Settings->KeepAliveIntervalMs);
// arg2 = arg2 = Settings->KeepAliveIntervalMs = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpKeepAliveIntervalMs
#define _clog_3_ARGS_TRACE_SettingDumpKeepAliveIntervalMs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpKeepAliveIntervalMs , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpIdleTimeoutMs
// [sett] IdleTimeoutMs          = %llu
// QuicTraceLogVerbose(SettingDumpIdleTimeoutMs,           "[sett] IdleTimeoutMs          = %llu", Settings->IdleTimeoutMs);
// arg2 = arg2 = Settings->IdleTimeoutMs = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpIdleTimeoutMs
#define _clog_3_ARGS_TRACE_SettingDumpIdleTimeoutMs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpIdleTimeoutMs , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpHandshakeIdleTimeoutMs
// [sett] HandshakeIdleTimeoutMs = %llu
// QuicTraceLogVerbose(SettingDumpHandshakeIdleTimeoutMs,  "[sett] HandshakeIdleTimeoutMs = %llu", Settings->HandshakeIdleTimeoutMs);
// arg2 = arg2 = Settings->HandshakeIdleTimeoutMs = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpHandshakeIdleTimeoutMs
#define _clog_3_ARGS_TRACE_SettingDumpHandshakeIdleTimeoutMs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpHandshakeIdleTimeoutMs , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpBidiStreamCount
// [sett] PeerBidiStreamCount    = %hu
// QuicTraceLogVerbose(SettingDumpBidiStreamCount,         "[sett] PeerBidiStreamCount    = %hu", Settings->PeerBidiStreamCount);
// arg2 = arg2 = Settings->PeerBidiStreamCount = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpBidiStreamCount
#define _clog_3_ARGS_TRACE_SettingDumpBidiStreamCount(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpBidiStreamCount , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpUnidiStreamCount
// [sett] PeerUnidiStreamCount   = %hu
// QuicTraceLogVerbose(SettingDumpUnidiStreamCount,        "[sett] PeerUnidiStreamCount   = %hu", Settings->PeerUnidiStreamCount);
// arg2 = arg2 = Settings->PeerUnidiStreamCount = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpUnidiStreamCount
#define _clog_3_ARGS_TRACE_SettingDumpUnidiStreamCount(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpUnidiStreamCount , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpTlsClientMaxSendBuffer
// [sett] TlsClientMaxSendBuffer = %u
// QuicTraceLogVerbose(SettingDumpTlsClientMaxSendBuffer,  "[sett] TlsClientMaxSendBuffer = %u", Settings->TlsClientMaxSendBuffer);
// arg2 = arg2 = Settings->TlsClientMaxSendBuffer = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpTlsClientMaxSendBuffer
#define _clog_3_ARGS_TRACE_SettingDumpTlsClientMaxSendBuffer(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpTlsClientMaxSendBuffer , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpTlsServerMaxSendBuffer
// [sett] TlsServerMaxSendBuffer = %u
// QuicTraceLogVerbose(SettingDumpTlsServerMaxSendBuffer,  "[sett] TlsServerMaxSendBuffer = %u", Settings->TlsServerMaxSendBuffer);
// arg2 = arg2 = Settings->TlsServerMaxSendBuffer = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpTlsServerMaxSendBuffer
#define _clog_3_ARGS_TRACE_SettingDumpTlsServerMaxSendBuffer(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpTlsServerMaxSendBuffer , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpStreamRecvWindowDefault
// [sett] StreamRecvWindowDefault= %u
// QuicTraceLogVerbose(SettingDumpStreamRecvWindowDefault, "[sett] StreamRecvWindowDefault= %u", Settings->StreamRecvWindowDefault);
// arg2 = arg2 = Settings->StreamRecvWindowDefault = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpStreamRecvWindowDefault
#define _clog_3_ARGS_TRACE_SettingDumpStreamRecvWindowDefault(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpStreamRecvWindowDefault , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpStreamRecvBufferDefault
// [sett] StreamRecvBufferDefault= %u
// QuicTraceLogVerbose(SettingDumpStreamRecvBufferDefault, "[sett] StreamRecvBufferDefault= %u", Settings->StreamRecvBufferDefault);
// arg2 = arg2 = Settings->StreamRecvBufferDefault = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpStreamRecvBufferDefault
#define _clog_3_ARGS_TRACE_SettingDumpStreamRecvBufferDefault(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpStreamRecvBufferDefault , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpConnFlowControlWindow
// [sett] ConnFlowControlWindow  = %u
// QuicTraceLogVerbose(SettingDumpConnFlowControlWindow,   "[sett] ConnFlowControlWindow  = %u", Settings->ConnFlowControlWindow);
// arg2 = arg2 = Settings->ConnFlowControlWindow = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpConnFlowControlWindow
#define _clog_3_ARGS_TRACE_SettingDumpConnFlowControlWindow(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpConnFlowControlWindow , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxBytesPerKey
// [sett] MaxBytesPerKey         = %llu
// QuicTraceLogVerbose(SettingDumpMaxBytesPerKey,          "[sett] MaxBytesPerKey         = %llu", Settings->MaxBytesPerKey);
// arg2 = arg2 = Settings->MaxBytesPerKey = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpMaxBytesPerKey
#define _clog_3_ARGS_TRACE_SettingDumpMaxBytesPerKey(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMaxBytesPerKey , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpServerResumptionLevel
// [sett] ServerResumptionLevel  = %hhu
// QuicTraceLogVerbose(SettingDumpServerResumptionLevel,   "[sett] ServerResumptionLevel  = %hhu", Settings->ServerResumptionLevel);
// arg2 = arg2 = Settings->ServerResumptionLevel = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpServerResumptionLevel
#define _clog_3_ARGS_TRACE_SettingDumpServerResumptionLevel(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpServerResumptionLevel , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpVersionNegoExtEnabled
// [sett] Version Negotiation Ext Enabled = %hhu
// QuicTraceLogVerbose(SettingDumpVersionNegoExtEnabled,   "[sett] Version Negotiation Ext Enabled = %hhu", Settings->VersionNegotiationExtEnabled);
// arg2 = arg2 = Settings->VersionNegotiationExtEnabled = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpVersionNegoExtEnabled
#define _clog_3_ARGS_TRACE_SettingDumpVersionNegoExtEnabled(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpVersionNegoExtEnabled , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpMinimumMtu
// [sett] MinimumMtu             = %hu
// QuicTraceLogVerbose(SettingDumpMinimumMtu,              "[sett] MinimumMtu             = %hu", Settings->MinimumMtu);
// arg2 = arg2 = Settings->MinimumMtu = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpMinimumMtu
#define _clog_3_ARGS_TRACE_SettingDumpMinimumMtu(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMinimumMtu , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaximumMtu
// [sett] MaximumMtu             = %hu
// QuicTraceLogVerbose(SettingDumpMaximumMtu,              "[sett] MaximumMtu             = %hu", Settings->MaximumMtu);
// arg2 = arg2 = Settings->MaximumMtu = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpMaximumMtu
#define _clog_3_ARGS_TRACE_SettingDumpMaximumMtu(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMaximumMtu , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpMtuCompleteTimeout
// [sett] MtuCompleteTimeout     = %llu
// QuicTraceLogVerbose(SettingDumpMtuCompleteTimeout,      "[sett] MtuCompleteTimeout     = %llu", Settings->MtuDiscoverySearchCompleteTimeoutUs);
// arg2 = arg2 = Settings->MtuDiscoverySearchCompleteTimeoutUs = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpMtuCompleteTimeout
#define _clog_3_ARGS_TRACE_SettingDumpMtuCompleteTimeout(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMtuCompleteTimeout , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpMtuMissingProbeCount
// [sett] MtuMissingProbeCount   = %hhu
// QuicTraceLogVerbose(SettingDumpMtuMissingProbeCount,    "[sett] MtuMissingProbeCount   = %hhu", Settings->MtuDiscoveryMissingProbeCount);
// arg2 = arg2 = Settings->MtuDiscoveryMissingProbeCount = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpMtuMissingProbeCount
#define _clog_3_ARGS_TRACE_SettingDumpMtuMissingProbeCount(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMtuMissingProbeCount , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxBindingStatelessOper
// [sett] MaxBindingStatelessOper= %hu
// QuicTraceLogVerbose(SettingDumpMaxBindingStatelessOper, "[sett] MaxBindingStatelessOper= %hu", Settings->MaxBindingStatelessOperations);
// arg2 = arg2 = Settings->MaxBindingStatelessOperations = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpMaxBindingStatelessOper
#define _clog_3_ARGS_TRACE_SettingDumpMaxBindingStatelessOper(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMaxBindingStatelessOper , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpStatelessOperExpirMs
// [sett] StatelessOperExpirMs   = %hu
// QuicTraceLogVerbose(SettingDumpStatelessOperExpirMs,    "[sett] StatelessOperExpirMs   = %hu", Settings->StatelessOperationExpirationMs);
// arg2 = arg2 = Settings->StatelessOperationExpirationMs = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpStatelessOperExpirMs
#define _clog_3_ARGS_TRACE_SettingDumpStatelessOperExpirMs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpStatelessOperExpirMs , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingCongestionControlAlgorithm
// [sett] CongestionControlAlgorithm = %hu
// QuicTraceLogVerbose(SettingCongestionControlAlgorithm,  "[sett] CongestionControlAlgorithm = %hu", Settings->CongestionControlAlgorithm);
// arg2 = arg2 = Settings->CongestionControlAlgorithm = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingCongestionControlAlgorithm
#define _clog_3_ARGS_TRACE_SettingCongestionControlAlgorithm(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingCongestionControlAlgorithm , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpAcceptedVersionsLength
// [sett] AcceptedVersionslength = %u
// QuicTraceLogVerbose(SettingDumpAcceptedVersionsLength,      "[sett] AcceptedVersionslength = %u", Settings->VersionSettings->AcceptableVersionsLength);
// arg2 = arg2 = Settings->VersionSettings->AcceptableVersionsLength = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpAcceptedVersionsLength
#define _clog_3_ARGS_TRACE_SettingDumpAcceptedVersionsLength(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpAcceptedVersionsLength , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpOfferedVersionsLength
// [sett] OfferedVersionslength  = %u
// QuicTraceLogVerbose(SettingDumpOfferedVersionsLength,       "[sett] OfferedVersionslength  = %u", Settings->VersionSettings->OfferedVersionsLength);
// arg2 = arg2 = Settings->VersionSettings->OfferedVersionsLength = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SettingDumpOfferedVersionsLength
#define _clog_3_ARGS_TRACE_SettingDumpOfferedVersionsLength(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpOfferedVersionsLength , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpAcceptableVersions
// [sett] AcceptableVersions[%u]  = 0x%x
// QuicTraceLogVerbose(SettingDumpAcceptableVersions,      "[sett] AcceptableVersions[%u]  = 0x%x", i, Settings->VersionSettings->AcceptableVersions[i]);
// arg2 = arg2 = i = arg2
// arg3 = arg3 = Settings->VersionSettings->AcceptableVersions[i] = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_SettingDumpAcceptableVersions
#define _clog_4_ARGS_TRACE_SettingDumpAcceptableVersions(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SETTINGS_C, SettingDumpAcceptableVersions , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpOfferedVersions
// [sett] OfferedVersions[%u]     = 0x%x
// QuicTraceLogVerbose(SettingDumpOfferedVersions,         "[sett] OfferedVersions[%u]     = 0x%x", i, Settings->VersionSettings->OfferedVersions[i]);
// arg2 = arg2 = i = arg2
// arg3 = arg3 = Settings->VersionSettings->OfferedVersions[i] = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_SettingDumpOfferedVersions
#define _clog_4_ARGS_TRACE_SettingDumpOfferedVersions(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SETTINGS_C, SettingDumpOfferedVersions , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingDumpFullyDeployedVersions
// [sett] FullyDeployedVersion[%u]= 0x%x
// QuicTraceLogVerbose(SettingDumpFullyDeployedVersions,   "[sett] FullyDeployedVersion[%u]= 0x%x", i, Settings->VersionSettings->FullyDeployedVersions[i]);
// arg2 = arg2 = i = arg2
// arg3 = arg3 = Settings->VersionSettings->FullyDeployedVersions[i] = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_SettingDumpFullyDeployedVersions
#define _clog_4_ARGS_TRACE_SettingDumpFullyDeployedVersions(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SETTINGS_C, SettingDumpFullyDeployedVersions , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingsInvalidAcceptableVersion
// Invalid AcceptableVersion supplied to settings! 0x%x at position %d
// QuicTraceLogError(
                SettingsInvalidAcceptableVersion,
                "Invalid AcceptableVersion supplied to settings! 0x%x at position %d",
                Settings->AcceptableVersions[i],
                (int32_t)i);
// arg2 = arg2 = Settings->AcceptableVersions[i] = arg2
// arg3 = arg3 = (int32_t)i = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_SettingsInvalidAcceptableVersion
#define _clog_4_ARGS_TRACE_SettingsInvalidAcceptableVersion(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SETTINGS_C, SettingsInvalidAcceptableVersion , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingsInvalidOfferedVersion
// Invalid OfferedVersion supplied to settings! 0x%x at position %d
// QuicTraceLogError(
                SettingsInvalidOfferedVersion,
                "Invalid OfferedVersion supplied to settings! 0x%x at position %d",
                Settings->OfferedVersions[i],
                (int32_t)i);
// arg2 = arg2 = Settings->OfferedVersions[i] = arg2
// arg3 = arg3 = (int32_t)i = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_SettingsInvalidOfferedVersion
#define _clog_4_ARGS_TRACE_SettingsInvalidOfferedVersion(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SETTINGS_C, SettingsInvalidOfferedVersion , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SettingsInvalidFullyDeployedVersion
// Invalid FullyDeployedVersion supplied to settings! 0x%x at position %d
// QuicTraceLogError(
                SettingsInvalidFullyDeployedVersion,
                "Invalid FullyDeployedVersion supplied to settings! 0x%x at position %d",
                Settings->FullyDeployedVersions[i],
                (int32_t)i);
// arg2 = arg2 = Settings->FullyDeployedVersions[i] = arg2
// arg3 = arg3 = (int32_t)i = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_SettingsInvalidFullyDeployedVersion
#define _clog_4_ARGS_TRACE_SettingsInvalidFullyDeployedVersion(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SETTINGS_C, SettingsInvalidFullyDeployedVersion , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "VersionSettings",
            AllocSize);
// arg2 = arg2 = "VersionSettings" = arg2
// arg3 = arg3 = AllocSize = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SETTINGS_C, AllocFailure , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_settings.c.clog.h.c"
#endif
