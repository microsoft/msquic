/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include <windows.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <msquic.h>

#include <stdint.h>

enum QuicEventIdGlobal {
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

    EventId_QuicLibraryCount
};

enum QuicEventIdWorker {
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
};

enum QuicEventIdConnection {
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
    EventId_QuicConnStats,
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

    EventId_QuicConnCount
};

enum QuicEventIdStream {
    EventId_QuicStreamCreated,
    EventId_QuicStreamDestroyed,
    EventId_QuicStreamOutFlowBlocked,
    EventId_QuicStreamRundown,
    EventId_QuicStreamSendState,
    EventId_QuicStreamRecvState,
    EventId_QuicStreamError,
    EventId_QuicStreamErrorStatus,

    EventId_QuicStreamCount
} ;

#pragma pack(push)
#pragma pack(1)

struct QuicGlobalEventPayload {
    union {
        struct {
            uint32_t PartitionCount;
            uint32_t DatapathFeatures;
        } LibraryInitialized, LibraryRundown;
        struct {
            char Desc[1];
            // uint64_t ByteCount - TODO
        } QuicAllocFailure;
        struct {
            char ErrStr[1];
        } Error;
        struct {
            uint32_t Status;
            char ErrStr[1];
        } ErrorStatus;
        struct {
            uint32_t Line;
            char File[1];
            // char Expression[1];
        } Assert;
        struct {
            uint32_t Type;
            uint8_t Handle[8];
        } ApiEnter;
        struct {
            uint32_t Status;
        } ApiExitStatus;
        struct {
            uint16_t CounterLen;
            int64_t Counters[QUIC_PERF_COUNTER_MAX];
        } PerfCounters;
    };
};

struct QuicWorkerEventPayload {
    union {
        struct {
            uint8_t IdealProcessor;
            uint8_t OwnerPtr[8];
        } Created;
        struct {
            uint8_t IsActive;
            uint32_t Arg;
        } ActivityStateUpdated;
        struct {
            uint32_t QueueDelay;
        } QueueDelayUpdated;
        struct {
            char ErrStr[1];
        } Error;
        struct {
            uint32_t Status;
            char ErrStr[1];
        } ErrorStatus;
    };
};

struct QuicConnEventPayload {
    union {
        struct {
            uint32_t IsServer;
            uint64_t CorrelationId;
        } Created, Rundown;
        struct {
            uint32_t State;
        } ScheduleState;
        struct {
            uint32_t Type;
        } ExecOper;
        struct {
            uint32_t Type;
        } ExecApiOper;
        struct {
            uint32_t Type;
        } ExecTimerOper;
        struct {
            uint8_t AddrLength;
            SOCKADDR_INET Addr;
        } RemoteAddrAdd, RemoteAddrRemove;
        struct {
            uint8_t AddrLength;
            SOCKADDR_INET Addr;
        } LocalAddrAdd, LocalAddrRemove;
        struct {
            uint8_t WorkerPtr[8];
        } AssignWorker;
        struct {
            uint8_t SessionPtr[8];
        } RegisterSession, UnregisterSession;
        struct {
            uint64_t ErrorCode;
            uint8_t IsRemoteShutdown;
            uint8_t IsQuicStatus;
        } TransportShutdown;
        struct {
            uint64_t ErrorCode;
            uint8_t IsRemoteShutdown;
        } AppShutdown;
        struct {
            uint32_t Version;
        } VersionSet;
        struct {
            uint64_t BytesSent;
            uint32_t BytesInFlight;
            uint32_t BytesInFlightMax;
            uint32_t CongestionWindow;
            uint32_t SlowStartThreshold;
            uint64_t ConnectionFlowControl;
            uint64_t IdealBytes;
            uint64_t PostedBytes;
            uint32_t SmoothedRtt;
        } OutFlowStats;
        struct {
            uint8_t ReasonFlags;
        } OutFlowBlocked;
        struct {
            uint64_t BytesRecv;
        } InFlowStats;
        struct {
            uint32_t SlowStartThreshold;
            uint32_t K;
            uint32_t WindowMax;
            uint32_t WindowLastMax;
        } Cubic;
        struct {
            uint64_t SequenceNumber;
            uint8_t CidLength;
            uint8_t Cid[1];
        } SourceCidAdd, SourceCidRemove;
        struct {
            uint64_t SequenceNumber;
            uint8_t CidLength;
            uint8_t Cid[1];
        } DestCidAdd, DestCidRemove;
        struct {
            uint8_t Type;
            uint32_t DelayMs;
            uint16_t ProbeCount;
        } LossDetectionTimerSet;
        struct {
            uint64_t PktNum;
            uint8_t Addrs[1]; // LocalAddr, RemoteAddr
            // char Reason[];
        } DropPacket;
        struct {
            uint64_t PktNum;
            uint64_t Value;
            uint8_t Addrs[1]; // LocalAddr, RemoteAddr
            // char Reason[];
        } DropPacketEx;
        struct {
            char ErrStr[1];
        } Error;
        struct {
            uint32_t Status;
            char ErrStr[1];
        } ErrorStatus;
        struct {
            uint8_t IsLocallyInitiated;
        } KeyPhaseChange;
        struct {
            uint32_t SmoothedRtt;
            uint32_t CongestionCount;
            uint32_t PersistentCongestionCount;
            uint64_t SendTotalBytes;
            uint64_t RecvTotalBytes;
        } Stats;
        struct {
            uint8_t TimedOut;
        } ShutdownComplete;
        struct {
            uint8_t NewValue;
        } ReadKeyUpdated, WriteKeyUpdated;
        struct {
            uint64_t Number;
            uint8_t Type;
            uint16_t Length;
        } PacketSent, PacketRecv;
        struct {
            uint64_t Number;
            uint8_t Type;
            uint8_t Reason;
        } PacketLost;
        struct {
            uint64_t Number;
            uint8_t Type;
        } PacketACKed;
        struct {
            char Msg[1];
        } Log;
        struct {
            UINT32 Reason;
        } QueueSendFlush;
        struct {
            uint64_t StreamFlowControl;
            uint64_t StreamSendWindow;
        } OutFlowStreamStats;
        struct {
            uint64_t SendTotalPackets;
            uint64_t SendSuspectedLostPackets;
            uint64_t SendSpuriousLostPackets;
            uint64_t RecvTotalPackets;
            uint64_t RecvReorderedPackets;
            uint64_t RecvDroppedPackets;
            uint64_t RecvDuplicatePackets;
            uint64_t RecvDecryptionFailures;
        } PacketStats;
    };
};


struct QuicStreamEventPayload {
    union {
        struct {
            uint8_t ConnectionPtr[8];
            //uint64_t ID;
            //uint8_t IsLocalOwned;
        } Created, Rundown;
        struct {
            uint8_t ReasonFlags;
        } OutFlowBlocked;
        struct {
            uint8_t State;
        } SendState;
        struct {
            uint8_t State;
        } RecvState;
        struct {
            char ErrStr[1];
        } Error;
        struct {
            uint32_t Status;
            char ErrStr[1];
        } ErrorStatus;
    };
};

#pragma pack(pop)
