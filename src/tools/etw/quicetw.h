/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quic_platform.h"
#include "msquic.h"
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdio.h>
#include <stdlib.h>

#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union

#include "object_set.h"
#include "qjson.h"

typedef struct _CXN CXN;
typedef struct _WORKER WORKER;
typedef struct _SESSION SESSION;
typedef struct _LISTENER LISTENER;
typedef struct _BINDING BINDING;

#define CAP_TO_32(uint64) (uint64 > UINT_MAX ? UINT_MAX : (ULONG)uint64)

#define QUIC_API_COUNT 26

#pragma warning(disable:4200)  // nonstandard extension used: zero-sized array in struct/union
#pragma warning(disable:4366)  // The result of the unary '&' operator may be unaligned

typedef
void
ObjEventCallback(
    _In_ PEVENT_RECORD ev,
    _Out_ ULONG* ObjectId,
    _Out_ BOOLEAN* TraceEvent,
    _Out_ ULONG64* InitialTimestamp
    );

typedef ObjEventCallback* ObjEventHandler;

extern const char* ApiTypeStr[QUIC_API_COUNT];

typedef enum QUIC_EVENT_TYPE {
    EventType_Global,
    EventType_Registration,
    EventType_Worker,
    EventType_Session,
    EventType_Listener,
    EventType_Connection,
    EventType_Stream,
    EventType_Binding,
    EventType_Tls,
    EventType_Datapath,
    EventType_Log,

    EventType_Count
} QUIC_EVENT_TYPE;

inline QUIC_EVENT_TYPE GetEventType(USHORT Id)
{
    return (QUIC_EVENT_TYPE)((Id >> 10) & 0xF);
}

inline USHORT GetEventId(USHORT Id)
{
    return Id & 0x3FF;
}

typedef enum QUIC_EVENT_ID_GLOBAL {
    EventId_QuicLibraryInitialized = 1,
    EventId_QuicLibraryUninitialized,
    EventId_QuicLibraryAddRef,
    EventId_QuicLibraryRelease,
    EventId_QuicLibraryWorkerPoolInit,
    EventId_QuicAllocFailure,
    EventId_QuicLibraryRundown,
    EventId_QuicLibraryError,
    EventId_QuicLibraryErrorStatus,
    EventId_QuicLibraryAssert,
    EventId_QuicApiEnter,
    EventId_QuicApiExit,
    EventId_QuicApiExitStatus,
    EventId_QuicApiWaitOperation,
    EventId_QuicPerfCountersRundown,
    EventId_QuicLibrarySendRetryStateUpdated,

    EventId_QuicLibraryCount
} QUIC_EVENT_ID_GLOBAL;

#define CXPLAT_DATAPATH_FEATURE_RECV_SIDE_SCALING     0x0001
#define CXPLAT_DATAPATH_FEATURE_RECV_COALESCING       0x0002
#define CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION     0x0004

#pragma pack(push)
#pragma pack(1)
typedef struct QUIC_EVENT_DATA_GLOBAL {
    union {
        struct {
            UINT32 PartitionCount;
            UINT32 DatapathFeatures;
        } LibraryInitialized, LibraryRundown;
        struct {
            char Desc[1];
            // UINT64 ByteCount - TODO
        } QuicAllocFailure;
        struct {
            char ErrStr[1];
        } Error;
        struct {
            UINT32 Status;
            char ErrStr[1];
        } ErrorStatus;
        struct {
            UINT32 Line;
            char File[1];
            // char Expression[1];
        } Assert;
        struct {
            UINT32 Type;
            ULONG_PTR Handle;
        } ApiEnter;
        struct {
            UINT32 Status;
        } ApiExitStatus;
        struct {
            uint16_t CounterLen;
            int64_t Counters[QUIC_PERF_COUNTER_MAX];
        } PerfCounters;
        struct {
            UINT8 Value;
        } LibrarySendRetryStateUpdated;
    };
} QUIC_EVENT_DATA_GLOBAL;
#pragma pack(pop)

typedef enum QUIC_EVENT_ID_REGISTRATION {
    EventId_QuicRegistrationCreated,
    EventId_QuicRegistrationDestroyed,
    EventId_QuicRegistrationCleanup,
    EventId_QuicRegistrationRundown,
    EventId_QuicRegistrationError,
    EventId_QuicRegistrationErrorStatus,

    EventId_QuicRegistrationCount
} QUIC_EVENT_ID_REGISTRATION;

#pragma pack(push)
#pragma pack(1)
typedef struct QUIC_EVENT_DATA_REGISTRATION {
    ULONG_PTR RegistrationPtr;
    union {
        struct {
            char AppName[1];
        } Created, Rundown;
        struct {
            char ErrStr[1];
        } Error;
        struct {
            UINT32 Status;
            char ErrStr[1];
        } ErrorStatus;
    };
} QUIC_EVENT_DATA_REGISTRATION;
#pragma pack(pop)

typedef enum QUIC_EVENT_ID_WORKER {
    EventId_QuicWorkerCreated,
    EventId_QuicWorkerStart,
    EventId_QuicWorkerStop,
    EventId_QuicWorkerActivityStateUpdated,
    EventId_QuicWorkerQueueDelayUpdated,
    EventId_QuicWorkerDestroyed,
    EventId_QuicWorkerCleanup,
    EventId_QuicWorkerError,
    EventId_QuicWorkerErrorStatus,

    EventId_QuicWorkerCount
} QUIC_EVENT_ID_WORKER;

#pragma pack(push)
#pragma pack(1)
typedef struct QUIC_EVENT_DATA_WORKER {
    ULONG_PTR WorkerPtr;
    union {
        struct {
            UINT8 IdealProcessor;
            ULONG_PTR OwnerPtr;
        } Created;
        struct {
            UINT8 IsActive;
            UINT32 Arg;
        } ActivityStateUpdated;
        struct {
            UINT32 QueueDelay;
        } QueueDelayUpdated;
        struct {
            char ErrStr[1];
        } Error;
        struct {
            UINT32 Status;
            char ErrStr[1];
        } ErrorStatus;
    };
} QUIC_EVENT_DATA_WORKER;
#pragma pack(pop)

typedef enum QUIC_EVENT_ID_SESSION {
    EventId_QuicSessionCreated,
    EventId_QuicSessionDestroyed,
    EventId_QuicSessionCleanup,
    EventId_QuicSessionShutdown,
    EventId_QuicSessionRundown,
    EventId_QuicSessionError,
    EventId_QuicSessionErrorStatus,

    EventId_QuicSessionCount
} QUIC_EVENT_ID_SESSION;

#pragma pack(push)
#pragma pack(1)
typedef struct QUIC_EVENT_DATA_SESSION {
    ULONG_PTR SessionPtr;
    union {
        struct {
            ULONG_PTR RegistrationPtr;
            char Alpn[1];
        } Created, Rundown;
        struct {
            UINT32 Flags;
            ULONG64 ErrorCode;
        } Shutdown;
        struct {
            char ErrStr[1];
        } Error;
        struct {
            UINT32 Status;
            char ErrStr[1];
        } ErrorStatus;
    };
} QUIC_EVENT_DATA_SESSION;
#pragma pack(pop)

typedef enum QUIC_EVENT_ID_LISTENER {
    EventId_QuicListenerCreated,
    EventId_QuicListenerDestroyed,
    EventId_QuicListenerStarted,
    EventId_QuicListenerStopped,
    EventId_QuicListenerRundown,
    EventId_QuicListenerError,
    EventId_QuicListenerErrorStatus,

    EventId_QuicListenerCount
} QUIC_EVENT_ID_LISTENER;

#pragma pack(push)
#pragma pack(1)
typedef struct QUIC_EVENT_DATA_LISTENER {
    ULONG_PTR ListenerPtr;
    union {
        struct {
            ULONG_PTR SessionPtr;
        } Created, Rundown;
        struct {
            ULONG_PTR BindingPtr;
            UINT8 AddrLength;
            SOCKADDR_INET Addr;
        } Started;
        struct {
            char ErrStr[1];
        } Error;
        struct {
            UINT32 Status;
            char ErrStr[1];
        } ErrorStatus;
    };
} QUIC_EVENT_DATA_LISTENER;
#pragma pack(pop)

typedef enum QUIC_EVENT_ID_CONNECTION {
    EventId_QuicConnCreated,
    EventId_QuicConnDestroyed,
    EventId_QuicConnHandshakeComplete,
    EventId_QuicConnScheduleState,
    EventId_QuicConnExecOper,
    EventId_QuicConnExecApiOper,
    EventId_QuicConnExecTimerOper,
    EventId_QuicConnLocalAddrAdded,
    EventId_QuicConnRemoteAddrAdded,
    EventId_QuicConnLocalAddrRemoved,
    EventId_QuicConnRemoteAddrRemoved,
    EventId_QuicConnAssignWorker,
    EventId_QuicConnHandshakeStart,
    EventId_QuicConnRegisterSession,
    EventId_QuicConnUnregisterSession,
    EventId_QuicConnTransportShutdown,
    EventId_QuicConnAppShutdown,
    EventId_QuicConnInitializeComplete,
    EventId_QuicConnHandleClosed,
    EventId_QuicConnVersionSet,
    EventId_QuicConnOutFlowStats,
    EventId_QuicConnOutFlowBlocked,
    EventId_QuicConnInFlowStats,
    EventId_QuicConnCubic,
    EventId_QuicConnCongestion,
    EventId_QuicConnPersistentCongestion,
    EventId_QuicConnRecoveryExit,
    EventId_QuicConnRundown,
    EventId_QuicConnSourceCidAdded,
    EventId_QuicConnDestCidAdded,
    EventId_QuicConnSourceCidRemoved,
    EventId_QuicConnDestCidRemoved,
    EventId_QuicConnLossDetectionTimerSet,
    EventId_QuicConnLossDetectionTimerCancel,
    EventId_QuicConnDropPacket,
    EventId_QuicConnDropPacketEx,
    EventId_QuicConnError,
    EventId_QuicConnErrorStatus,
    EventId_QuicConnNewPacketKeys,
    EventId_QuicConnKeyPhaseChange,
    EventId_QuicConnStatistics,
    EventId_QuicConnShutdownComplete,
    EventId_QuicConnReadKeyUpdated,
    EventId_QuicConnWriteKeyUpdated,
    EventId_QuicConnPacketSent,
    EventId_QuicConnPacketRecv,
    EventId_QuicConnPacketLost,
    EventId_QuicConnPacketACKed,
    EventId_QuicConnLogError,
    EventId_QuicConnLogWarning,
    EventId_QuicConnLogInfo,
    EventId_QuicConnLogVerbose,
    EventId_QuicConnQueueSendFlush,
    EventId_QuicConnOutFlowStreamStats,
    EventId_QuicConnPacketStats,
    EventId_QuicConnServerResumeTicket,
    EventId_QuicConnVNEOtherVersionList,
    EventId_QuicConnClientReceivedVersionList,
    EventId_QuicConnServerSupportedVersionList,

    EventId_QuicConnCount
} QUIC_EVENT_ID_CONNECTION;

#pragma pack(push)
#pragma pack(1)
typedef struct QUIC_EVENT_DATA_CONNECTION {
    ULONG_PTR CxnPtr;
    union {
        struct {
            UINT32 IsServer;
            UINT64 CorrelationId;
        } Created, Rundown;
        struct {
            UINT32 State;
        } ScheduleState;
        struct {
            UINT32 Type;
        } ExecOper;
        struct {
            UINT32 Type;
        } ExecApiOper;
        struct {
            UINT32 Type;
        } ExecTimerOper;
        struct {
            UINT8 AddrLength;
            SOCKADDR_INET Addr;
        } RemoteAddrAdd, RemoteAddrRemove;
        struct {
            UINT8 AddrLength;
            SOCKADDR_INET Addr;
        } LocalAddrAdd, LocalAddrRemove;
        struct {
            ULONG_PTR WorkerPtr;
        } AssignWorker;
        struct {
            ULONG_PTR SessionPtr;
        } RegisterSession, UnregisterSession;
        struct {
            ULONG64 ErrorCode;
            UINT8 IsRemoteShutdown;
            UINT8 IsQuicStatus;
        } TransportShutdown;
        struct {
            ULONG64 ErrorCode;
            UINT8 IsRemoteShutdown;
        } AppShutdown;
        struct {
            UINT32 Version;
        } VersionSet;
        struct {
            UINT64 BytesSent;
            UINT32 BytesInFlight;
            UINT32 BytesInFlightMax;
            UINT32 CongestionWindow;
            UINT32 SlowStartThreshold;
            UINT64 ConnectionFlowControl;
            UINT64 IdealBytes;
            UINT64 PostedBytes;
            UINT32 SmoothedRtt;
        } OutFlowStats;
        struct {
            UINT8 ReasonFlags;
        } OutFlowBlocked;
        struct {
            UINT64 BytesRecv;
        } InFlowStats;
        struct {
            UINT32 SlowStartThreshold;
            UINT32 K;
            UINT32 WindowMax;
            UINT32 WindowLastMax;
        } Cubic;
        struct {
            UINT64 SequenceNumber;
            UINT8 CidLength;
            UINT8 Cid[1];
        } SourceCidAdd, SourceCidRemove;
        struct {
            UINT64 SequenceNumber;
            UINT8 CidLength;
            UINT8 Cid[1];
        } DestCidAdd, DestCidRemove;
        struct {
            UINT8 Type;
            UINT32 DelayMs;
            UINT16 ProbeCount;
        } LossDetectionTimerSet;
        struct {
            UINT8 Addrs[1]; // LocalAddr, RemoteAddr
            // char Reason[];
        } DropPacket;
        struct {
            UINT64 Value;
            UINT8 Addrs[1]; // LocalAddr, RemoteAddr
            // char Reason[];
        } DropPacketEx;
        struct {
            char ErrStr[1];
        } Error;
        struct {
            UINT32 Status;
            char ErrStr[1];
        } ErrorStatus;
        struct {
            UINT8 IsLocallyInitiated;
        } KeyPhaseChange;
        struct {
            UINT32 SmoothedRtt;
            UINT32 CongestionCount;
            UINT32 PersistentCongestionCount;
            UINT64 SendTotalBytes;
            UINT64 RecvTotalBytes;
        } Stats;
        struct {
            UINT8 TimedOut;
        } ShutdownComplete;
        struct {
            UINT8 NewValue;
        } ReadKeyUpdated, WriteKeyUpdated;
        struct {
            UINT64 Number;
            UINT8 Type;
            UINT16 Length;
        } PacketSent, PacketRecv;
        struct {
            UINT64 Number;
            UINT8 Type;
            UINT8 Reason;
        } PacketLost;
        struct {
            UINT64 Number;
            UINT8 Type;
        } PacketACKed;
        struct {
            char Msg[1];
        } Log;
        struct {
            UINT32 Reason;
        } QueueSendFlush;
        struct {
            UINT64 StreamFlowControl;
            UINT64 StreamSendWindow;
        } OutFlowStreamStats;
        struct {
            UINT64 SendTotalPackets;
            UINT64 SendSuspectedLostPackets;
            UINT64 SendSpuriousLostPackets;
            UINT64 RecvTotalPackets;
            UINT64 RecvReorderedPackets;
            UINT64 RecvDroppedPackets;
            UINT64 RecvDuplicatePackets;
            UINT64 RecvDecryptionFailures;
        } PacketStats;
    };
} QUIC_EVENT_DATA_CONNECTION;
#pragma pack(pop)

typedef enum QUIC_EVENT_ID_STREAM {
    EventId_QuicStreamCreated,
    EventId_QuicStreamDestroyed,
    EventId_QuicStreamOutFlowBlocked,
    EventId_QuicStreamRundown,
    EventId_QuicStreamSendState,
    EventId_QuicStreamRecvState,
    EventId_QuicStreamError,
    EventId_QuicStreamErrorStatus,
    EventId_QuicStreamLogError,
    EventId_QuicStreamLogWarning,
    EventId_QuicStreamLogInfo,
    EventId_QuicStreamLogVerbose,

    EventId_QuicStreamCount
} QUIC_EVENT_ID_STREAM;

#define STREAM_ID_FLAG_IS_SERVER        0b01
#define STREAM_ID_FLAG_IS_UNI_DIR       0b10

#pragma pack(push)
#pragma pack(1)
typedef struct QUIC_EVENT_DATA_STREAM {
    ULONG_PTR StreamPtr;
    union {
        struct {
            ULONG_PTR ConnectionPtr;
            UINT64 ID;
            UINT8 IsLocalOwned;
        } Created, Rundown;
        struct {
            UINT8 ReasonFlags;
        } OutFlowBlocked;
        struct {
            UINT8 State;
        } SendState;
        struct {
            UINT8 State;
        } RecvState;
        struct {
            char ErrStr[1];
        } Error;
        struct {
            UINT32 Status;
            char ErrStr[1];
        } ErrorStatus;
        struct {
            char Msg[1];
        } Log;
    };
} QUIC_EVENT_DATA_STREAM;
#pragma pack(pop)

typedef enum QUIC_EVENT_ID_BINDING {
    EventId_QuicBindingCreated,
    EventId_QuicBindingRundown,
    EventId_QuicBindingDestroyed,
    EventId_QuicBindingCleanup,
    EventId_QuicBindingDropPacket,
    EventId_QuicBindingDropPacketEx,
    EventId_QuicBindingError,
    EventId_QuicBindingErrorStatus,
    EventId_QuicBindingExecOper,

    EventId_QuicBindingCount
} QUIC_EVENT_ID_BINDING;

#pragma pack(push)
#pragma pack(1)
typedef struct QUIC_EVENT_DATA_BINDING {
    ULONG_PTR BindingPtr;
    union {
        struct {
            ULONG_PTR DatapathPtr;
            UINT8 Addrs[1]; // LocalAddr, RemoteAddr
        } Created, Rundown;
        struct {
            UINT8 Addrs[1]; // LocalAddr, RemoteAddr
        } DropPacket;
        struct {
            UINT64 Value;
            UINT8 Addrs[1]; // LocalAddr, RemoteAddr
        } DropPacketEx;
        struct {
            char ErrStr[1];
        } Error;
        struct {
            UINT32 Status;
            char ErrStr[1];
        } ErrorStatus;
        struct {
            UINT32 Type;
        } ExecOper;
    };
} QUIC_EVENT_DATA_BINDING;
#pragma pack(pop)

typedef enum QUIC_EVENT_ID_TLS {
    EventId_QuicTlsError,
    EventId_QuicTlsErrorStatus,
    EventId_QuicTlsMessage,

    EventId_QuicTlsCount
} QUIC_EVENT_ID_TLS;

#pragma pack(push)
#pragma pack(1)
typedef struct QUIC_EVENT_DATA_TLS {
    ULONG_PTR CxnPtr;
    union {
        struct {
            char ErrStr[1];
        } Error;
        struct {
            UINT32 Status;
            char ErrStr[1];
        } ErrorStatus;
        struct {
            char Str[1];
        } Message;
    };
} QUIC_EVENT_DATA_TLS;
#pragma pack(pop)

typedef enum QUIC_EVENT_ID_DATAPATH {
    EventId_QuicDatapathDEPRECATED,
    EventId_QuicDatapathSend,
    EventId_QuicDatapathRecv,
    EventId_QuicDatapathError,
    EventId_QuicDatapathErrorStatus,

    EventId_QuicDatapathCount
} QUIC_EVENT_ID_DATAPATH;

#pragma pack(push)
#pragma pack(1)
typedef struct QUIC_EVENT_DATA_DATAPATH {
    ULONG_PTR BindingPtr;
    union {
        struct {
            UINT32 TotalSize;
            UINT8 BufferCount;
            UINT16 SegmentSize;
            UINT8 Addrs[1]; // RemoteAddr, LocalAddr
        } Send;
        struct {
            UINT32 TotalSize;
            UINT16 SegmentSize;
            UINT8 Addrs[1]; // LocalAddr, RemoteAddr
        } Recv;
        struct {
            char ErrStr[1];
        } Error;
        struct {
            UINT32 Status;
            char ErrStr[1];
        } ErrorStatus;
    };
} QUIC_EVENT_DATA_DATAPATH;
#pragma pack(pop)

typedef enum QUIC_EVENT_ID_LOG {
    EventId_QuicLogError,
    EventId_QuicLogWarning,
    EventId_QuicLogInfo,
    EventId_QuicLogVerbose,

    EventId_QuicLogCount
} QUIC_EVENT_ID_LOG;

#pragma pack(push)
#pragma pack(1)
typedef struct QUIC_EVENT_DATA_LOG {
    char Msg[1];
} QUIC_EVENT_DATA_LOG;
#pragma pack(pop)

inline void AddrToString(const SOCKADDR_INET* Addr, _Out_ char AddrStr[INET6_ADDRSTRLEN])
{
    ULONG AddrStrLen = INET6_ADDRSTRLEN;
    if (Addr->si_family == QUIC_ADDRESS_FAMILY_UNSPEC) {
        if (Addr->Ipv4.sin_port == 0) {
            strcpy_s(AddrStr, INET6_ADDRSTRLEN, "NotSet");
        } else {
            sprintf_s(AddrStr, INET6_ADDRSTRLEN, "Unspecified:%u", Addr->Ipv4.sin_port);
        }
    } else if (Addr->si_family == QUIC_ADDRESS_FAMILY_INET) {
        RtlIpv4AddressToStringExA(&Addr->Ipv4.sin_addr, Addr->Ipv4.sin_port, AddrStr, &AddrStrLen);
    } else if (Addr->si_family == QUIC_ADDRESS_FAMILY_INET6) {
        RtlIpv6AddressToStringExA(&Addr->Ipv6.sin6_addr, Addr->Ipv6.sin6_scope_id, Addr->Ipv6.sin6_port, AddrStr, &AddrStrLen);
    } else {
        strcpy_s(AddrStr, INET6_ADDRSTRLEN, "Invalid");
    }
}

inline const uint8_t* DecodeAddr(const uint8_t* Addr, _Out_ char AddrStr[INET6_ADDRSTRLEN])
{
    uint8_t Len = Addr[0];
    AddrToString((SOCKADDR_INET*)(Addr+1), AddrStr);
    return Addr + 1 + Len;
}

#define QUIC_CID_MAX_STR_LEN 37

inline void CidToString(UINT8 CidLength, const UINT8* Cid, _Out_ char CidStr[QUIC_CID_MAX_STR_LEN])
{
    if (CidLength == 0) {
        strcpy_s(CidStr, QUIC_CID_MAX_STR_LEN, "null");
    } else {
        for (UINT8 i = 0; i < CidLength; i++) {
            sprintf_s(
                CidStr + i*2, QUIC_CID_MAX_STR_LEN - i*2,
                "%.2X", Cid[i]);
        }
    }
}

typedef enum _TRI_STATE {
    TRI_FALSE,
    TRI_TRUE,
    TRI_UNKNOWN,
} TRI_STATE;

inline const char* TriStateToString(TRI_STATE State)
{
    switch (State) {
    case TRI_FALSE: return "FALSE";
    case TRI_TRUE:  return "TRUE";
    default:        return "UNKNOWN";
    }
}

typedef enum _COMMAND_TYPE {
    COMMAND_NONE,
    COMMAND_SUMMARY,
    COMMAND_REPORT,
    COMMAND_TRACE,
    COMMAND_CONN,
    COMMAND_CONN_LIST,
    COMMAND_CONN_TPUT,
    COMMAND_CONN_TRACE,
    COMMAND_CONN_QLOG,
    COMMAND_WORKER,
    COMMAND_WORKER_LIST,
    COMMAND_WORKER_QUEUE,
    COMMAND_WORKER_TRACE,
    COMMAND_STREAM_TRACE
} COMMAND_TYPE;

typedef enum _SORT_TYPE {
    SORT_NONE,
    SORT_AGE,
    SORT_CPU_ACTIVE,
    SORT_CPU_QUEUED,
    SORT_CPU_IDLE,
    SORT_TX,
    SORT_RX,
    SORT_CXN_COUNT,
    SORT_SHUTDOWN_TIME,
} SORT_TYPE;

inline SORT_TYPE StringToSortType(const char* str)
{
    if (!strcmp(str, "age")) {
        return SORT_AGE;
    } else if (!strcmp(str, "cpu_active")) {
        return SORT_CPU_ACTIVE;
    } else if (!strcmp(str, "cpu_queued")) {
        return SORT_CPU_QUEUED;
    } else if (!strcmp(str, "cpu_idle")) {
        return SORT_CPU_IDLE;
    } else if (!strcmp(str, "tx")) {
        return SORT_TX;
    } else if (!strcmp(str, "rx")) {
        return SORT_RX;
    } else if (!strcmp(str, "conn_count")) {
        return SORT_CXN_COUNT;
    } else if (!strcmp(str, "shutdown")) {
        return SORT_SHUTDOWN_TIME;
    } else {
        return SORT_NONE;
    }
}

typedef enum _FILTER_TYPE {
    FILTER_NONE = 0x0,
    FILTER_DISCONNECT = 0x1,
} FILTER_TYPE;

inline FILTER_TYPE StringToFilterType(const char* str)
{
    // TODO - Support multiple filters in semicolon deliminated list.
    if (!strcmp(str, "disconnect")) {
        return FILTER_DISCONNECT;
    } else {
        return FILTER_NONE;
    }
}

typedef enum QUIC_SCHEDULE_STATE {
    QUIC_SCHEDULE_IDLE,
    QUIC_SCHEDULE_QUEUED,
    QUIC_SCHEDULE_PROCESSING,
    QUIC_SCHEDULE_MAX
} QUIC_SCHEDULE_STATE;

typedef struct QUIC_TIME_STATS {
    ULONG Count;
    ULONG MinCpuTime;       // usec
    ULONG MaxCpuTime;       // usec
    ULONG64 TotalCpuTime;   // usec
} QUIC_TIME_STATS;

inline void InitCpuTime(QUIC_TIME_STATS* Stats)
{
    memset(Stats, 0, sizeof(*Stats));
    Stats->MinCpuTime = ULONG_MAX;
}

inline void AddCpuTime(QUIC_TIME_STATS* Stats, ULONG64 CpuTime)
{
    Stats->Count++;
    Stats->TotalCpuTime += CpuTime;
    if (CpuTime < (ULONG64)Stats->MinCpuTime) {
        Stats->MinCpuTime = (ULONG)CpuTime;
    }
    if (CpuTime > (ULONG64)Stats->MaxCpuTime) {
        Stats->MaxCpuTime = (ULONG)CpuTime;
    }
}

inline ULONG AvgCpuTime(const QUIC_TIME_STATS* Stats)
{
    return Stats->Count == 0 ? 0 : (ULONG)(Stats->TotalCpuTime / Stats->Count);
}

inline void PrintTimeUs(ULONG64 TimeUs)
{
    if (TimeUs > 1000 * 1000) {
        TimeUs /= 1000;
        printf("%llu.%llu s", TimeUs / 1000, TimeUs % 1000);
    } else if (TimeUs > 1000) {
        printf("%llu.%llu ms", TimeUs / 1000, TimeUs % 1000);
    } else {
        printf("%llu us", TimeUs);
    }
}

inline void PrintCpuTime(QUIC_TIME_STATS* Stats)
{
    if (Stats->Count == 0) {
        printf("null\n");
        return;
    }

    PrintTimeUs(Stats->TotalCpuTime);
    printf(" (avg ");
    PrintTimeUs(Stats->TotalCpuTime / Stats->Count);
    printf(", min ");
    PrintTimeUs(Stats->MinCpuTime);
    printf(", max ");
    PrintTimeUs(Stats->MaxCpuTime);
    printf(")\n");
}

typedef struct _WORKER {
    struct _OBJECT;
    ULONG ThreadId;
    UCHAR IdealProcessor;
    ULONG64 OwnerPtr;
    BOOLEAN IsIdle;

    ULONG64 InitialTimestamp; // 100ns
    ULONG64 StartTimestamp; // 100ns
    ULONG64 StopTimestamp; // 100ns
    ULONG64 FinalTimestamp; // 100ns

    QUIC_TIME_STATS SchedulingStats[QUIC_SCHEDULE_MAX];
    ULONG64 ProcessorBitmap;

    ULONG64 LastActiveTimestamp; // 100ns
    ULONG64 TotalActiveTime; // 100ns

    ULONG TotalCxnCount;
    ULONG CxnCount;
    ULONG CxnQueueCount;

    // Sampling values
    ULONG SampleCount;
    ULONG64 QueueDelaySamples;
    ULONG64 CxnProcessSamples;
    ULONG64 LastQueueOutputTimestamp; // 100ns
    ULONG64 LastQueueSampleTimestamp; // 100ns
} WORKER;

typedef struct _LISTENER {
    struct _OBJECT;

    ULONG64 InitialTimestamp; // 100ns
    ULONG64 FinalTimestamp; // 100ns
} LISTENER;

typedef struct _SESSION {
    struct _OBJECT;

    ULONG64 InitialTimestamp; // 100ns
    ULONG64 FinalTimestamp; // 100ns
} SESSION;

typedef struct _CID {
    struct _CID* Next;
    UINT8 Length;
    UINT8 Buffer[0];
} CID;

typedef struct _CXN {
    struct _OBJECT;
    ULONG64 CorrelationId;
    TRI_STATE IsServer;
    TRI_STATE HandshakeStarted;
    TRI_STATE HandshakeCompleted;
    TRI_STATE Shutdown;
    BOOLEAN Destroyed;              // Pointer freed or reused.
    BOOLEAN StatsProcessed;
    SOCKADDR_INET LocalAddress;
    SOCKADDR_INET RemoteAddress;
    UCHAR InitialProcessor;

    struct _CID* SrcCids;
    struct _CID* DestCids;

    ULONG64 WorkerPtr;
    struct _WORKER* Worker;

    ULONG64 SessionPtr;

    struct _STREAM* Streams;
    ULONG64 StreamCount;

    ULONG ErrorCount;

    ULONG64 InitialTimestamp; // 100ns
    ULONG64 FinalTimestamp; // 100ns

    ULONG64 ShutdownTimestamp; // 100ns
    UINT8 ShutdownIsApp;
    ULONG64 ShutdownErrorCode;
    UINT8 ShutdownIsRemote;
    UINT8 ShutdownIsQuicStatus;

    // Scheduling state changes
    QUIC_SCHEDULE_STATE ScheduleState;
    ULONG64 ScheduleStateTimestamp; // 100ns
    QUIC_TIME_STATS SchedulingStats[QUIC_SCHEDULE_MAX];
    ULONG64 ProcessorBitmap;

    // Payload counters
    ULONG64 BytesSent;
    ULONG64 BytesReceived;

    // Sampling values
    ULONG64 LastTraceSampleTimestamp; // 100ns
    ULONG64 LastBytesSent;
    ULONG64 LastBytesReceived;
    ULONG SmoothedRtt; // usec
    ULONG CongestionWindow;
    ULONG BytesInFlight;
    ULONG InRecovery;
    ULONG SampleInRecovery;
    ULONG64 TxBufBytes;
    ULONG64 ConnFlowAvailable;
    ULONG64 StreamFlowAvailable;
    ULONG64 StreamSendWindow;
    ULONG SlowStartThreshold;
    ULONG CubicK;
    ULONG CubicWindowMax;
    ULONG CongestionEvents;
    ULONG PersistentCongestionEvents;

    // Stats values
    ULONG64 SentPackets;
    ULONG64 LostPackets;
    ULONG64 ReceivedPackets;
    ULONG64 DroppedPackets;
} CXN;

inline
BOOLEAN
CxnWasDisconnected(
    const CXN* Cxn
    )
{
    return
        Cxn->Shutdown == TRI_TRUE &&
        !Cxn->ShutdownIsApp &&
        Cxn->ShutdownIsQuicStatus; // TODO - Check for disconnect status
}

typedef struct _STREAM {
    struct _OBJECT;
    ULONG64 StreamId;

    ULONG64 CxnPtr;
    struct _CXN* Cxn;

    struct _STREAM* Next; // For CXN->Streams list.

    ULONG64 InitialTimestamp; // 100ns
    ULONG64 FinalTimestamp; // 100ns
} STREAM;

typedef struct _BINDING {
    struct _OBJECT;

    ULONG64 InitialTimestamp; // 100ns
    ULONG64 FinalTimestamp; // 100ns
} BINDING;

typedef struct _CMD_ARGS {
    COMMAND_TYPE Command;
    BOOLEAN FormatCSV;
    BOOLEAN Verbose;
    SORT_TYPE Sort;
    FILTER_TYPE Filter;
    ULONG SelectedId;
    ULONG64 OutputResolution;
    ULONG MaxOutputLines;
    UINT8 Cid[256];
    UINT8 CidLength;
} CMD_ARGS;

typedef struct _TRACE_STATE {
    BOOLEAN Processed;
    TRACEHANDLE Handle;
    ULONG64 ProcessedMs;

    ULONG64 StartTimestamp;
    ULONG64 StopTimestamp;

    ULONG64 EventCount;
    ULONG64 EventTypeCount[EventType_Count];
    ULONG64 ApiCallCount;
    ULONG OutputLineCount;

    BOOLEAN HasSchedulingEvents;
    BOOLEAN HasDatapathEvents;
} TRACE_STATE;

typedef struct EVENT_COUNTS {
    const char* Name; ULONG64* Counts; USHORT Length;
} EVENT_COUNTS;

typedef struct API_STATS {
    ULONG Count;
    //
    // TODO - Calculate min/max & P50/90/99
    //
} API_STATS;

extern CMD_ARGS Cmd;
extern TRACE_STATE Trace;
extern EVENT_COUNTS EventCounts[EventType_Count];
extern API_STATS ApiStats[QUIC_API_COUNT];

extern OBJECT_SET Workers;
extern OBJECT_SET Sessions;
extern OBJECT_SET Listeners;
extern OBJECT_SET Cxns;
extern OBJECT_SET Streams;
extern OBJECT_SET Bindings;

extern QJSON* Qj; // Used for writing qlog files

void ExecuteSummaryCommand(void);
void ExecuteReportCommand(void);
void ExecuteWorkerCommand(void);
void ExecuteCxnCommand(void);

void RunProcessTrace(void);

ObjEventCallback LibraryEventCallback;
ObjEventCallback WorkerEventCallback;
ObjEventCallback SessionEventCallback;
ObjEventCallback ListenerEventCallback;
ObjEventCallback ConnEventCallback;
ObjEventCallback StreamEventCallback;
ObjEventCallback BindingEventCallback;
ObjEventCallback TlsEventCallback;

void
QuicTraceEvent(
    _In_ PEVENT_RECORD ev,
    _In_ ULONG ObjectId,
    _In_ ULONG64 InitialTimestamp
    );

void
OutputWorkerQueueSample(
    _In_ WORKER* Worker,
    _In_ ULONG64 NewTimeStamp,
    _In_ ULONG64 NewQueueDelay
    );

_Ret_maybenull_
WORKER*
GetWorkerFromThreadId(
    _In_ ULONG ThreadId
    );

//
// QUIC protocol helpers
//

inline UINT8 DecodeHexChar(char c)
{
    if (c >= '0' && c <= '9') return (UINT8)(c - '0');
    if (c >= 'A' && c <= 'F') return (UINT8)(10 + c - 'A');
    if (c >= 'a' && c <= 'f') return (UINT8)(10 + c - 'a');
    return 0;
}

inline void ReadCid(_In_z_ const char* Cid)
{
    Cmd.CidLength = (UINT8)strlen(Cid) / 2;
    for (UINT8 i = 0; i < Cmd.CidLength; i++) {
        Cmd.Cid[i] =
            (DecodeHexChar(Cid[i * 2]) << 4) |
             DecodeHexChar(Cid[i * 2 + 1]);
    }
}

#define QUIC_ERROR_NO_ERROR                     0x0
#define QUIC_ERROR_INTERNAL_ERROR               0x1
#define QUIC_ERROR_CONNECTION_REFUSED           0x2
#define QUIC_ERROR_FLOW_CONTROL_ERROR           0x3
#define QUIC_ERROR_STREAM_LIMIT_ERROR           0x4
#define QUIC_ERROR_STREAM_STATE_ERROR           0x5
#define QUIC_ERROR_FINAL_SIZE_ERROR             0x6
#define QUIC_ERROR_FRAME_ENCODING_ERROR         0x7
#define QUIC_ERROR_TRANSPORT_PARAMETER_ERROR    0x8
#define QUIC_ERROR_PROTOCOL_VIOLATION           0xA
#define QUIC_ERROR_CRYPTO_BUFFER_EXCEEDED       0xD
#define QUIC_ERROR_KEY_UPDATE_ERROR             0xE
#define QUIC_ERROR_AEAD_LIMIT_REACHED           0xF

#define QUIC_ERROR_CRYPTO_ERROR_MASK            0x1FF

#define TLS_ERROR_HANDSHAKE_FAILURE             40

inline
const char*
QuicErrorToString(
    _In_ UINT64 ErrorCode
    )
{
    if (ErrorCode < 0x100) {
        switch (ErrorCode) {
        case QUIC_ERROR_NO_ERROR:                   return "NO_ERROR";
        case QUIC_ERROR_INTERNAL_ERROR:             return "INTERNAL_ERROR";
        case QUIC_ERROR_CONNECTION_REFUSED:         return "CONNECTION_REFUSED";
        case QUIC_ERROR_FLOW_CONTROL_ERROR:         return "FLOW_CONTROL_ERROR";
        case QUIC_ERROR_STREAM_LIMIT_ERROR:         return "STREAM_LIMIT_ERROR";
        case QUIC_ERROR_STREAM_STATE_ERROR:         return "STREAM_STATE_ERROR";
        case QUIC_ERROR_FINAL_SIZE_ERROR:           return "FINAL_SIZE_ERROR";
        case QUIC_ERROR_FRAME_ENCODING_ERROR:       return "FRAME_ENCODING_ERROR";
        case QUIC_ERROR_TRANSPORT_PARAMETER_ERROR:  return "TRANSPORT_PARAMETER_ERROR";
        case QUIC_ERROR_PROTOCOL_VIOLATION:         return "PROTOCOL_VIOLATION";
        case QUIC_ERROR_CRYPTO_BUFFER_EXCEEDED:     return "CRYPTO_BUFFER_EXCEEDED";
        case QUIC_ERROR_KEY_UPDATE_ERROR:           return "CRYPTO_BUFFER_EXCEEDED";
        case QUIC_ERROR_AEAD_LIMIT_REACHED:         return "KEY_UPDATE_ERROR";
        default:                                    return "UNDEFINED ERROR CODE";
        }
    } else if (ErrorCode < 0x200) {
        switch (ErrorCode & 0xFF) {
        case TLS_ERROR_HANDSHAKE_FAILURE:       return "TLS ERROR (Handshake Failure)";
        default:                                return "TLS ERROR (other)";
        }
    } else {
        return "UNDEFINED ERROR CODE";
    }
}
