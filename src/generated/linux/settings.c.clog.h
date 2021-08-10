#include <clog.h>
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
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_3_ARGS_TRACE_SettingDumpSendBufferingEnabled



/*----------------------------------------------------------
// Decoder Ring for SettingDumpSendBufferingEnabled
// [sett] SendBufferingEnabled   = %hhu
// QuicTraceLogVerbose(SettingDumpSendBufferingEnabled,    "[sett] SendBufferingEnabled   = %hhu", Settings->SendBufferingEnabled);
// arg2 = arg2 = Settings->SendBufferingEnabled
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpSendBufferingEnabled(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpSendBufferingEnabled , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpPacingEnabled



/*----------------------------------------------------------
// Decoder Ring for SettingDumpPacingEnabled
// [sett] PacingEnabled          = %hhu
// QuicTraceLogVerbose(SettingDumpPacingEnabled,           "[sett] PacingEnabled          = %hhu", Settings->PacingEnabled);
// arg2 = arg2 = Settings->PacingEnabled
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpPacingEnabled(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpPacingEnabled , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpMigrationEnabled



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMigrationEnabled
// [sett] MigrationEnabled       = %hhu
// QuicTraceLogVerbose(SettingDumpMigrationEnabled,        "[sett] MigrationEnabled       = %hhu", Settings->MigrationEnabled);
// arg2 = arg2 = Settings->MigrationEnabled
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpMigrationEnabled(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMigrationEnabled , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpDatagramReceiveEnabled



/*----------------------------------------------------------
// Decoder Ring for SettingDumpDatagramReceiveEnabled
// [sett] DatagramReceiveEnabled = %hhu
// QuicTraceLogVerbose(SettingDumpDatagramReceiveEnabled,  "[sett] DatagramReceiveEnabled = %hhu", Settings->DatagramReceiveEnabled);
// arg2 = arg2 = Settings->DatagramReceiveEnabled
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpDatagramReceiveEnabled(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpDatagramReceiveEnabled , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpMaxOperationsPerDrain



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxOperationsPerDrain
// [sett] MaxOperationsPerDrain  = %hhu
// QuicTraceLogVerbose(SettingDumpMaxOperationsPerDrain,   "[sett] MaxOperationsPerDrain  = %hhu", Settings->MaxOperationsPerDrain);
// arg2 = arg2 = Settings->MaxOperationsPerDrain
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpMaxOperationsPerDrain(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMaxOperationsPerDrain , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpRetryMemoryLimit



/*----------------------------------------------------------
// Decoder Ring for SettingDumpRetryMemoryLimit
// [sett] RetryMemoryLimit       = %hu
// QuicTraceLogVerbose(SettingDumpRetryMemoryLimit,        "[sett] RetryMemoryLimit       = %hu", Settings->RetryMemoryLimit);
// arg2 = arg2 = Settings->RetryMemoryLimit
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpRetryMemoryLimit(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpRetryMemoryLimit , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpLoadBalancingMode



/*----------------------------------------------------------
// Decoder Ring for SettingDumpLoadBalancingMode
// [sett] LoadBalancingMode      = %hu
// QuicTraceLogVerbose(SettingDumpLoadBalancingMode,       "[sett] LoadBalancingMode      = %hu", Settings->LoadBalancingMode);
// arg2 = arg2 = Settings->LoadBalancingMode
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpLoadBalancingMode(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpLoadBalancingMode , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpMaxStatelessOperations



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxStatelessOperations
// [sett] MaxStatelessOperations = %u
// QuicTraceLogVerbose(SettingDumpMaxStatelessOperations,  "[sett] MaxStatelessOperations = %u", Settings->MaxStatelessOperations);
// arg2 = arg2 = Settings->MaxStatelessOperations
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpMaxStatelessOperations(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMaxStatelessOperations , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpMaxWorkerQueueDelayUs



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxWorkerQueueDelayUs
// [sett] MaxWorkerQueueDelayUs  = %u
// QuicTraceLogVerbose(SettingDumpMaxWorkerQueueDelayUs,   "[sett] MaxWorkerQueueDelayUs  = %u", Settings->MaxWorkerQueueDelayUs);
// arg2 = arg2 = Settings->MaxWorkerQueueDelayUs
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpMaxWorkerQueueDelayUs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMaxWorkerQueueDelayUs , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpInitialWindowPackets



/*----------------------------------------------------------
// Decoder Ring for SettingDumpInitialWindowPackets
// [sett] InitialWindowPackets   = %u
// QuicTraceLogVerbose(SettingDumpInitialWindowPackets,    "[sett] InitialWindowPackets   = %u", Settings->InitialWindowPackets);
// arg2 = arg2 = Settings->InitialWindowPackets
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpInitialWindowPackets(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpInitialWindowPackets , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpSendIdleTimeoutMs



/*----------------------------------------------------------
// Decoder Ring for SettingDumpSendIdleTimeoutMs
// [sett] SendIdleTimeoutMs      = %u
// QuicTraceLogVerbose(SettingDumpSendIdleTimeoutMs,       "[sett] SendIdleTimeoutMs      = %u", Settings->SendIdleTimeoutMs);
// arg2 = arg2 = Settings->SendIdleTimeoutMs
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpSendIdleTimeoutMs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpSendIdleTimeoutMs , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpInitialRttMs



/*----------------------------------------------------------
// Decoder Ring for SettingDumpInitialRttMs
// [sett] InitialRttMs           = %u
// QuicTraceLogVerbose(SettingDumpInitialRttMs,            "[sett] InitialRttMs           = %u", Settings->InitialRttMs);
// arg2 = arg2 = Settings->InitialRttMs
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpInitialRttMs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpInitialRttMs , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpMaxAckDelayMs



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxAckDelayMs
// [sett] MaxAckDelayMs          = %u
// QuicTraceLogVerbose(SettingDumpMaxAckDelayMs,           "[sett] MaxAckDelayMs          = %u", Settings->MaxAckDelayMs);
// arg2 = arg2 = Settings->MaxAckDelayMs
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpMaxAckDelayMs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMaxAckDelayMs , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpDisconnectTimeoutMs



/*----------------------------------------------------------
// Decoder Ring for SettingDumpDisconnectTimeoutMs
// [sett] DisconnectTimeoutMs    = %u
// QuicTraceLogVerbose(SettingDumpDisconnectTimeoutMs,     "[sett] DisconnectTimeoutMs    = %u", Settings->DisconnectTimeoutMs);
// arg2 = arg2 = Settings->DisconnectTimeoutMs
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpDisconnectTimeoutMs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpDisconnectTimeoutMs , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpKeepAliveIntervalMs



/*----------------------------------------------------------
// Decoder Ring for SettingDumpKeepAliveIntervalMs
// [sett] KeepAliveIntervalMs    = %u
// QuicTraceLogVerbose(SettingDumpKeepAliveIntervalMs,     "[sett] KeepAliveIntervalMs    = %u", Settings->KeepAliveIntervalMs);
// arg2 = arg2 = Settings->KeepAliveIntervalMs
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpKeepAliveIntervalMs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpKeepAliveIntervalMs , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpIdleTimeoutMs



/*----------------------------------------------------------
// Decoder Ring for SettingDumpIdleTimeoutMs
// [sett] IdleTimeoutMs          = %llu
// QuicTraceLogVerbose(SettingDumpIdleTimeoutMs,           "[sett] IdleTimeoutMs          = %llu", Settings->IdleTimeoutMs);
// arg2 = arg2 = Settings->IdleTimeoutMs
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpIdleTimeoutMs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpIdleTimeoutMs , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpHandshakeIdleTimeoutMs



/*----------------------------------------------------------
// Decoder Ring for SettingDumpHandshakeIdleTimeoutMs
// [sett] HandshakeIdleTimeoutMs = %llu
// QuicTraceLogVerbose(SettingDumpHandshakeIdleTimeoutMs,  "[sett] HandshakeIdleTimeoutMs = %llu", Settings->HandshakeIdleTimeoutMs);
// arg2 = arg2 = Settings->HandshakeIdleTimeoutMs
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpHandshakeIdleTimeoutMs(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpHandshakeIdleTimeoutMs , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpBidiStreamCount



/*----------------------------------------------------------
// Decoder Ring for SettingDumpBidiStreamCount
// [sett] PeerBidiStreamCount    = %hu
// QuicTraceLogVerbose(SettingDumpBidiStreamCount,         "[sett] PeerBidiStreamCount    = %hu", Settings->PeerBidiStreamCount);
// arg2 = arg2 = Settings->PeerBidiStreamCount
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpBidiStreamCount(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpBidiStreamCount , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpUnidiStreamCount



/*----------------------------------------------------------
// Decoder Ring for SettingDumpUnidiStreamCount
// [sett] PeerUnidiStreamCount   = %hu
// QuicTraceLogVerbose(SettingDumpUnidiStreamCount,        "[sett] PeerUnidiStreamCount   = %hu", Settings->PeerUnidiStreamCount);
// arg2 = arg2 = Settings->PeerUnidiStreamCount
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpUnidiStreamCount(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpUnidiStreamCount , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpTlsClientMaxSendBuffer



/*----------------------------------------------------------
// Decoder Ring for SettingDumpTlsClientMaxSendBuffer
// [sett] TlsClientMaxSendBuffer = %u
// QuicTraceLogVerbose(SettingDumpTlsClientMaxSendBuffer,  "[sett] TlsClientMaxSendBuffer = %u", Settings->TlsClientMaxSendBuffer);
// arg2 = arg2 = Settings->TlsClientMaxSendBuffer
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpTlsClientMaxSendBuffer(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpTlsClientMaxSendBuffer , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpTlsServerMaxSendBuffer



/*----------------------------------------------------------
// Decoder Ring for SettingDumpTlsServerMaxSendBuffer
// [sett] TlsServerMaxSendBuffer = %u
// QuicTraceLogVerbose(SettingDumpTlsServerMaxSendBuffer,  "[sett] TlsServerMaxSendBuffer = %u", Settings->TlsServerMaxSendBuffer);
// arg2 = arg2 = Settings->TlsServerMaxSendBuffer
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpTlsServerMaxSendBuffer(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpTlsServerMaxSendBuffer , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpStreamRecvWindowDefault



/*----------------------------------------------------------
// Decoder Ring for SettingDumpStreamRecvWindowDefault
// [sett] StreamRecvWindowDefault= %u
// QuicTraceLogVerbose(SettingDumpStreamRecvWindowDefault, "[sett] StreamRecvWindowDefault= %u", Settings->StreamRecvWindowDefault);
// arg2 = arg2 = Settings->StreamRecvWindowDefault
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpStreamRecvWindowDefault(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpStreamRecvWindowDefault , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpStreamRecvBufferDefault



/*----------------------------------------------------------
// Decoder Ring for SettingDumpStreamRecvBufferDefault
// [sett] StreamRecvBufferDefault= %u
// QuicTraceLogVerbose(SettingDumpStreamRecvBufferDefault, "[sett] StreamRecvBufferDefault= %u", Settings->StreamRecvBufferDefault);
// arg2 = arg2 = Settings->StreamRecvBufferDefault
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpStreamRecvBufferDefault(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpStreamRecvBufferDefault , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpConnFlowControlWindow



/*----------------------------------------------------------
// Decoder Ring for SettingDumpConnFlowControlWindow
// [sett] ConnFlowControlWindow  = %u
// QuicTraceLogVerbose(SettingDumpConnFlowControlWindow,   "[sett] ConnFlowControlWindow  = %u", Settings->ConnFlowControlWindow);
// arg2 = arg2 = Settings->ConnFlowControlWindow
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpConnFlowControlWindow(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpConnFlowControlWindow , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpMaxBytesPerKey



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxBytesPerKey
// [sett] MaxBytesPerKey         = %llu
// QuicTraceLogVerbose(SettingDumpMaxBytesPerKey,          "[sett] MaxBytesPerKey         = %llu", Settings->MaxBytesPerKey);
// arg2 = arg2 = Settings->MaxBytesPerKey
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpMaxBytesPerKey(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpMaxBytesPerKey , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpServerResumptionLevel



/*----------------------------------------------------------
// Decoder Ring for SettingDumpServerResumptionLevel
// [sett] ServerResumptionLevel  = %hhu
// QuicTraceLogVerbose(SettingDumpServerResumptionLevel,   "[sett] ServerResumptionLevel  = %hhu", Settings->ServerResumptionLevel);
// arg2 = arg2 = Settings->ServerResumptionLevel
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpServerResumptionLevel(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SETTINGS_C, SettingDumpServerResumptionLevel , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpSendBufferingEnabled



/*----------------------------------------------------------
// Decoder Ring for SettingDumpSendBufferingEnabled
// [sett] SendBufferingEnabled   = %hhu
// QuicTraceLogVerbose(SettingDumpSendBufferingEnabled,    "[sett] SendBufferingEnabled   = %hhu", Settings->SendBufferingEnabled);
// arg2 = arg2 = Settings->SendBufferingEnabled
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpSendBufferingEnabled(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpPacingEnabled



/*----------------------------------------------------------
// Decoder Ring for SettingDumpPacingEnabled
// [sett] PacingEnabled          = %hhu
// QuicTraceLogVerbose(SettingDumpPacingEnabled,           "[sett] PacingEnabled          = %hhu", Settings->PacingEnabled);
// arg2 = arg2 = Settings->PacingEnabled
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpPacingEnabled(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpMigrationEnabled



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMigrationEnabled
// [sett] MigrationEnabled       = %hhu
// QuicTraceLogVerbose(SettingDumpMigrationEnabled,        "[sett] MigrationEnabled       = %hhu", Settings->MigrationEnabled);
// arg2 = arg2 = Settings->MigrationEnabled
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpMigrationEnabled(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpDatagramReceiveEnabled



/*----------------------------------------------------------
// Decoder Ring for SettingDumpDatagramReceiveEnabled
// [sett] DatagramReceiveEnabled = %hhu
// QuicTraceLogVerbose(SettingDumpDatagramReceiveEnabled,  "[sett] DatagramReceiveEnabled = %hhu", Settings->DatagramReceiveEnabled);
// arg2 = arg2 = Settings->DatagramReceiveEnabled
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpDatagramReceiveEnabled(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpMaxOperationsPerDrain



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxOperationsPerDrain
// [sett] MaxOperationsPerDrain  = %hhu
// QuicTraceLogVerbose(SettingDumpMaxOperationsPerDrain,   "[sett] MaxOperationsPerDrain  = %hhu", Settings->MaxOperationsPerDrain);
// arg2 = arg2 = Settings->MaxOperationsPerDrain
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpMaxOperationsPerDrain(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpRetryMemoryLimit



/*----------------------------------------------------------
// Decoder Ring for SettingDumpRetryMemoryLimit
// [sett] RetryMemoryLimit       = %hu
// QuicTraceLogVerbose(SettingDumpRetryMemoryLimit,        "[sett] RetryMemoryLimit       = %hu", Settings->RetryMemoryLimit);
// arg2 = arg2 = Settings->RetryMemoryLimit
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpRetryMemoryLimit(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpLoadBalancingMode



/*----------------------------------------------------------
// Decoder Ring for SettingDumpLoadBalancingMode
// [sett] LoadBalancingMode      = %hu
// QuicTraceLogVerbose(SettingDumpLoadBalancingMode,       "[sett] LoadBalancingMode      = %hu", Settings->LoadBalancingMode);
// arg2 = arg2 = Settings->LoadBalancingMode
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpLoadBalancingMode(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpMaxStatelessOperations



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxStatelessOperations
// [sett] MaxStatelessOperations = %u
// QuicTraceLogVerbose(SettingDumpMaxStatelessOperations,  "[sett] MaxStatelessOperations = %u", Settings->MaxStatelessOperations);
// arg2 = arg2 = Settings->MaxStatelessOperations
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpMaxStatelessOperations(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpMaxWorkerQueueDelayUs



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxWorkerQueueDelayUs
// [sett] MaxWorkerQueueDelayUs  = %u
// QuicTraceLogVerbose(SettingDumpMaxWorkerQueueDelayUs,   "[sett] MaxWorkerQueueDelayUs  = %u", Settings->MaxWorkerQueueDelayUs);
// arg2 = arg2 = Settings->MaxWorkerQueueDelayUs
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpMaxWorkerQueueDelayUs(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpInitialWindowPackets



/*----------------------------------------------------------
// Decoder Ring for SettingDumpInitialWindowPackets
// [sett] InitialWindowPackets   = %u
// QuicTraceLogVerbose(SettingDumpInitialWindowPackets,    "[sett] InitialWindowPackets   = %u", Settings->InitialWindowPackets);
// arg2 = arg2 = Settings->InitialWindowPackets
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpInitialWindowPackets(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpSendIdleTimeoutMs



/*----------------------------------------------------------
// Decoder Ring for SettingDumpSendIdleTimeoutMs
// [sett] SendIdleTimeoutMs      = %u
// QuicTraceLogVerbose(SettingDumpSendIdleTimeoutMs,       "[sett] SendIdleTimeoutMs      = %u", Settings->SendIdleTimeoutMs);
// arg2 = arg2 = Settings->SendIdleTimeoutMs
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpSendIdleTimeoutMs(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpInitialRttMs



/*----------------------------------------------------------
// Decoder Ring for SettingDumpInitialRttMs
// [sett] InitialRttMs           = %u
// QuicTraceLogVerbose(SettingDumpInitialRttMs,            "[sett] InitialRttMs           = %u", Settings->InitialRttMs);
// arg2 = arg2 = Settings->InitialRttMs
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpInitialRttMs(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpMaxAckDelayMs



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxAckDelayMs
// [sett] MaxAckDelayMs          = %u
// QuicTraceLogVerbose(SettingDumpMaxAckDelayMs,           "[sett] MaxAckDelayMs          = %u", Settings->MaxAckDelayMs);
// arg2 = arg2 = Settings->MaxAckDelayMs
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpMaxAckDelayMs(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpDisconnectTimeoutMs



/*----------------------------------------------------------
// Decoder Ring for SettingDumpDisconnectTimeoutMs
// [sett] DisconnectTimeoutMs    = %u
// QuicTraceLogVerbose(SettingDumpDisconnectTimeoutMs,     "[sett] DisconnectTimeoutMs    = %u", Settings->DisconnectTimeoutMs);
// arg2 = arg2 = Settings->DisconnectTimeoutMs
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpDisconnectTimeoutMs(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpKeepAliveIntervalMs



/*----------------------------------------------------------
// Decoder Ring for SettingDumpKeepAliveIntervalMs
// [sett] KeepAliveIntervalMs    = %u
// QuicTraceLogVerbose(SettingDumpKeepAliveIntervalMs,     "[sett] KeepAliveIntervalMs    = %u", Settings->KeepAliveIntervalMs);
// arg2 = arg2 = Settings->KeepAliveIntervalMs
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpKeepAliveIntervalMs(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpIdleTimeoutMs



/*----------------------------------------------------------
// Decoder Ring for SettingDumpIdleTimeoutMs
// [sett] IdleTimeoutMs          = %llu
// QuicTraceLogVerbose(SettingDumpIdleTimeoutMs,           "[sett] IdleTimeoutMs          = %llu", Settings->IdleTimeoutMs);
// arg2 = arg2 = Settings->IdleTimeoutMs
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpIdleTimeoutMs(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpHandshakeIdleTimeoutMs



/*----------------------------------------------------------
// Decoder Ring for SettingDumpHandshakeIdleTimeoutMs
// [sett] HandshakeIdleTimeoutMs = %llu
// QuicTraceLogVerbose(SettingDumpHandshakeIdleTimeoutMs,  "[sett] HandshakeIdleTimeoutMs = %llu", Settings->HandshakeIdleTimeoutMs);
// arg2 = arg2 = Settings->HandshakeIdleTimeoutMs
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpHandshakeIdleTimeoutMs(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpBidiStreamCount



/*----------------------------------------------------------
// Decoder Ring for SettingDumpBidiStreamCount
// [sett] PeerBidiStreamCount    = %hu
// QuicTraceLogVerbose(SettingDumpBidiStreamCount,         "[sett] PeerBidiStreamCount    = %hu", Settings->PeerBidiStreamCount);
// arg2 = arg2 = Settings->PeerBidiStreamCount
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpBidiStreamCount(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpUnidiStreamCount



/*----------------------------------------------------------
// Decoder Ring for SettingDumpUnidiStreamCount
// [sett] PeerUnidiStreamCount   = %hu
// QuicTraceLogVerbose(SettingDumpUnidiStreamCount,        "[sett] PeerUnidiStreamCount   = %hu", Settings->PeerUnidiStreamCount);
// arg2 = arg2 = Settings->PeerUnidiStreamCount
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpUnidiStreamCount(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpTlsClientMaxSendBuffer



/*----------------------------------------------------------
// Decoder Ring for SettingDumpTlsClientMaxSendBuffer
// [sett] TlsClientMaxSendBuffer = %u
// QuicTraceLogVerbose(SettingDumpTlsClientMaxSendBuffer,  "[sett] TlsClientMaxSendBuffer = %u", Settings->TlsClientMaxSendBuffer);
// arg2 = arg2 = Settings->TlsClientMaxSendBuffer
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpTlsClientMaxSendBuffer(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpTlsServerMaxSendBuffer



/*----------------------------------------------------------
// Decoder Ring for SettingDumpTlsServerMaxSendBuffer
// [sett] TlsServerMaxSendBuffer = %u
// QuicTraceLogVerbose(SettingDumpTlsServerMaxSendBuffer,  "[sett] TlsServerMaxSendBuffer = %u", Settings->TlsServerMaxSendBuffer);
// arg2 = arg2 = Settings->TlsServerMaxSendBuffer
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpTlsServerMaxSendBuffer(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpStreamRecvWindowDefault



/*----------------------------------------------------------
// Decoder Ring for SettingDumpStreamRecvWindowDefault
// [sett] StreamRecvWindowDefault= %u
// QuicTraceLogVerbose(SettingDumpStreamRecvWindowDefault, "[sett] StreamRecvWindowDefault= %u", Settings->StreamRecvWindowDefault);
// arg2 = arg2 = Settings->StreamRecvWindowDefault
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpStreamRecvWindowDefault(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpStreamRecvBufferDefault



/*----------------------------------------------------------
// Decoder Ring for SettingDumpStreamRecvBufferDefault
// [sett] StreamRecvBufferDefault= %u
// QuicTraceLogVerbose(SettingDumpStreamRecvBufferDefault, "[sett] StreamRecvBufferDefault= %u", Settings->StreamRecvBufferDefault);
// arg2 = arg2 = Settings->StreamRecvBufferDefault
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpStreamRecvBufferDefault(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpConnFlowControlWindow



/*----------------------------------------------------------
// Decoder Ring for SettingDumpConnFlowControlWindow
// [sett] ConnFlowControlWindow  = %u
// QuicTraceLogVerbose(SettingDumpConnFlowControlWindow,   "[sett] ConnFlowControlWindow  = %u", Settings->ConnFlowControlWindow);
// arg2 = arg2 = Settings->ConnFlowControlWindow
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpConnFlowControlWindow(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpMaxBytesPerKey



/*----------------------------------------------------------
// Decoder Ring for SettingDumpMaxBytesPerKey
// [sett] MaxBytesPerKey         = %llu
// QuicTraceLogVerbose(SettingDumpMaxBytesPerKey,          "[sett] MaxBytesPerKey         = %llu", Settings->MaxBytesPerKey);
// arg2 = arg2 = Settings->MaxBytesPerKey
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpMaxBytesPerKey(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_SettingDumpServerResumptionLevel



/*----------------------------------------------------------
// Decoder Ring for SettingDumpServerResumptionLevel
// [sett] ServerResumptionLevel  = %hhu
// QuicTraceLogVerbose(SettingDumpServerResumptionLevel,   "[sett] ServerResumptionLevel  = %hhu", Settings->ServerResumptionLevel);
// arg2 = arg2 = Settings->ServerResumptionLevel
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SettingDumpServerResumptionLevel(uniqueId, encoded_arg_string, arg2)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_settings.c.clog.h.c"
#endif
