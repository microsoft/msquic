/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A helper library for processing MsQuic events and rebuilding the state of
    the system from them.

--*/

#include <stdint.h>
#include <algorithm>
#include <vector>

#pragma warning(disable:4200)  // nonstandard extension used: zero-sized array in struct/union

struct QuicStreamData;

#define UINT8_UNKNOWN UINT8_MAX
#define UINT16_UNKNOWN UINT16_MAX
#define UINT32_UNKNOWN UINT32_MAX
#define UINT64_UNKNOWN UINT64_MAX

enum QuicDataAvailableFlags {
    QuicDataAvailableNone                   = 0x0000,
    QuicDataAvailableApi                    = 0x0001,
    QuicDataAvailableWorker                 = 0x0002,
    QuicDataAvailableWorkerActivity         = 0x0004,
    QuicDataAvailableConnection             = 0x0008,
    QuicDataAvailableConnectionSchedule     = 0x0010,
    QuicDataAvailableConnectionFlowBlocked  = 0x0020,
    QuicDataAvailableConnectionExec         = 0x0040,
    QuicDataAvailableConnectionTput         = 0x0080,
    QuicDataAvailableStream                 = 0x0100,
    QuicDataAvailableStreamFlowBlocked      = 0x0200
};

inline QuicDataAvailableFlags& operator |= (QuicDataAvailableFlags& a, QuicDataAvailableFlags b) {
    return (QuicDataAvailableFlags&)(((uint32_t&)a) |= ((uint32_t)b));
}

enum QuicEventType {
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
};

enum QuicPointerSize {
    FourBytePointer,
    EightBytePointer
};

enum QuicTriState {
    TriFalse,
    TriTrue,
    TriUnknown
};

enum QuicConnectionState {
    ConnStateUnknown,
    ConnStateAllocated,
    ConnStateStarted,
    ConnStateHandshakeComplete,
    ConnStateShutdown,
    ConnStateClosed
};

enum QuicScheduleState {
    QuicScheduleIdle,
    QuicScheduleQueued,
    QuicScheduleProcessing
};

enum QuicExecutionType {
    ConnExecUnknown,

    ConnExecOperApi,
    ConnExecOperFlushRecv,
    ConnExecOperUnreachable,
    ConnExecOperFlushStreamRecv,
    ConnExecOperFlushSend,
    ConnExecOperTlsComplete,
    ConnExecOperTimerExpired,
    ConnExecOperTraceRundown,
    ConnExecOperVersionNegotiation,
    ConnExecOperStatelessReset,
    ConnExecOperRetry,

    ConnExecApiConnClose,
    ConnExecApiConnShutdown,
    ConnExecApiConnStart,
    ConnExecApiStreamClose,
    ConnExecApiStreamShutdown,
    ConnExecApiStreamStart,
    ConnExecApiStreamSendFlush,
    ConnExecApiStreamReceiveComplete,
    ConnExecApiStreamReceiveSetEnabled,
    ConnExecApiSetParam,
    ConnExecApiGetParam,

    ConnExecTimerPacing,
    ConnExecTimerAckDelay,
    ConnExecTimerLossDetection,
    ConnExecTimerKeepAlive,
    ConnExecTimerIdle,
    ConnExecTimerShutdown
};

enum QuicFlowBlockedFlags {
    QuicFlowBlockedNone                    = 0x00,
    QuicFlowBlockedScheduling              = 0x01,
    QuicFlowBlockedPacing                  = 0x02,
    QuicFlowBlockedAmplificationProtection = 0x04,
    QuicFlowBlockedCongestionControl       = 0x08,
    QuicFlowBlockedConnFlowControl         = 0x10,
    QuicFlowBlockedStreamIdFlowControl     = 0x20,
    QuicFlowBlockedStreamFlowControl       = 0x40,
    QuicFlowBlockedApp                     = 0x80
};

inline QuicFlowBlockedFlags& operator |= (QuicFlowBlockedFlags& a, QuicFlowBlockedFlags b) {
    return (QuicFlowBlockedFlags&)(((uint32_t&)a) |= ((uint32_t)b));
}

enum QuicApiType {
    QuicApiSetParam,
    QuicApiGetParam,
    QuicApiRegistrationOpen,
    QuicApiRegistrationClose,
    QuicApiConfigurationOpen,
    QuicApiConfigurationClose,
    QuicApiConfigurationLoadCredential,
    QuicApiSessionOpen,
    QuicApiSessionClose,
    QuicApiSessionShutdown,
    QuicApiListenerOpen,
    QuicApiListenerClose,
    QuicApiListenerStart,
    QuicApiListenerStop,
    QuicApiConnectionOpen,
    QuicApiConnectionClose,
    QuicApiConnectionShutdown,
    QuicApiConnectionStart,
    QuicApiConnectionSendResumptionTicket,
    QuicApiStreamOpen,
    QuicApiStreamClose,
    QuicApiStreamStart,
    QuicApiStreamShutdown,
    QuicApiStreamSend,
    QuicApiStreamReceiveComplete,
    QuicApiStreamReceiveSetEnabled,
    QuicApiDatagramSend
};

//
// Decodes the QUIC event type from the raw event ID.
//
inline uint16_t GetEventType(uint16_t Id) {
    return (uint16_t)((Id >> 10) & 0xF);
}

//
// Decodes the QUIC event ID from the raw event ID.
//
inline uint16_t GetEventId(uint16_t Id) {
    return Id & 0x3FF;
}

struct QuicEvent {
    uint32_t Type        : 8;   // QuicEventType
    uint32_t Processor   : 8;
    uint32_t Id          : 10;
    uint32_t PointerSize : 2;   // QuicPointerSize
    uint32_t Unused      : 4;
    uint32_t ProcessId;
    uint32_t ThreadId;
    uint64_t TimeStamp;         // Nanoseconds since start.
    uint16_t PayloadLength;
    uint8_t Payload[0];
};

struct QuicActivityData {
    uint64_t TimeStamp;
    uint64_t Duration;
};

struct QuicScheduleData {
    uint64_t TimeStamp;         // Nanoseconds
    uint32_t ThreadId;
    uint64_t Duration;          // Nanoseconds
    QuicScheduleState State;
};

struct QuicFlowBlockedData {
    uint64_t TimeStamp;         // Nanoseconds
    QuicFlowBlockedFlags Flags;
};

struct QuicExecutionData {
    uint64_t TimeStamp;         // Nanoseconds
    uint32_t ThreadId;
    uint8_t Processor;
    uint64_t Duration;          // Nanoseconds
    QuicExecutionType Type;
};

struct QuicThroughputData {
    uint64_t TimeStamp;         // Nanoseconds
    uint64_t Duration;          // Nanoseconds
    uint32_t RttUs;
    uint64_t TxRate;            // bps
    uint64_t RxRate;            // bps
    uint64_t BytesSent;
    uint64_t BytesReceived;
    uint32_t CongestionEvents;
    uint64_t BytesInFlight;
    uint32_t CongestionWindow;
    uint64_t BytesBufferedForSend;
    uint64_t FlowControlAvailable;
    uint64_t StreamFlowControlAvailable;
};

struct QuicWorkerData {
    uint32_t Id;
    uint64_t Ptr;
    uint32_t ProcessId;
    uint32_t ThreadId;
    uint16_t IdealProcessor;
    uint64_t ProcessorBitmap;

    uint64_t InitialTimeStamp;      // Nanoseconds
    uint64_t FinalTimeStamp;        // Nanoseconds
    uint64_t LastActiveTimeStamp;   // Nanoseconds
    uint64_t TotalActiveTime;       // Nanoseconds

    uint32_t TotalConnections;
    uint32_t CurrentConnections;

    virtual void GetActivityEvents(std::vector<QuicActivityData> &Events) const = 0;
};

struct QuicConnectionData {
    uint32_t Id;
    uint64_t Ptr;
    uint32_t ProcessId;
    uint64_t CorrelationId;
    uint64_t ProcessorBitmap;
    QuicConnectionState State;
    QuicTriState IsServer : 2;
    QuicTriState IsHandshakeComplete : 2;
    QuicTriState IsAppShutdown : 2;
    QuicTriState IsShutdownRemote : 2;

    uint64_t InitialTimeStamp;  // Nanoseconds
    uint64_t FinalTimeStamp;    // Nanoseconds
    uint64_t ShutdownTimeStamp; // Nanoseconds

    uint64_t BytesSent;
    uint64_t BytesReceived;

    QuicWorkerData* Worker;

    std::vector<QuicStreamData*> Streams;

    static bool SortByAge(const QuicConnectionData* A, const QuicConnectionData* B) {
        return (A->FinalTimeStamp - A->InitialTimeStamp) < (B->FinalTimeStamp - B->InitialTimeStamp);
    }

    virtual void GetScheduleEvents(std::vector<QuicScheduleData> &Events) const = 0;

    virtual void GetFlowBlockedEvents(std::vector<QuicFlowBlockedData> &Events) const = 0;

    virtual void GetMergedFlowBlockedEvents(std::vector<QuicFlowBlockedData> &Events) const = 0;

    virtual void GetExecEvents(std::vector<QuicExecutionData> &Events) const = 0;

    virtual void GetTputEvents(uint32_t ResolutionNs, std::vector<QuicThroughputData> &Events) const = 0;
};

struct QuicStreamData {
    uint32_t Id;
    uint64_t Ptr;
    uint64_t ProcessId;
    uint64_t StreamId;

    uint64_t InitialTimeStamp;      // Nanoseconds
    uint64_t FinalTimeStamp;        // Nanoseconds

    QuicConnectionData* Connection;

    virtual void GetFlowBlockedEvents(std::vector<QuicFlowBlockedData> &Events) const = 0;
};

struct QuicApiData {
    QuicApiType ApiType;
    uint8_t Processor;
    uint32_t ProcessId;
    uint32_t ThreadId;
    uint64_t TimeStamp;     // Nanoseconds
    uint64_t Duration;      // Nanoseconds
    uint64_t Ptr;
    uint32_t Result;
};

struct IQuicEventCollection {

    //
    // The function is called for each event from the whatever input source that
    // contains/generates the events. The collection takes ownership of the
    // event and calls free on it when it's done with it.
    //
    virtual void ProcessEvent(const QuicEvent* Event) = 0;

    //
    // Called when all events have now been processed.
    //
    virtual void Finalize() = 0;

    //
    // Returns a set of flags indicating what type of data is available.
    //
    virtual QuicDataAvailableFlags IsDataAvailable() const = 0;

    //
    // Returns the list of worker data objects.
    //
    virtual void GetWorkers(
        uint64_t BeginTimeStamp,    // Nanoseconds
        uint64_t EndTimeStamp,      // Nanoseconds
        std::vector<const QuicWorkerData*> &Workers) const = 0;

    //
    // Returns the list of connection data objects.
    //
    virtual void GetConnections(
        uint64_t BeginTimeStamp,    // Nanoseconds
        uint64_t EndTimeStamp,      // Nanoseconds
        std::vector<const QuicConnectionData*> &Connections) const = 0;

    //
    // Returns the list of API data objects.
    //
    virtual void GetApiCalls(
        uint64_t BeginTimeStamp,    // Nanoseconds
        uint64_t EndTimeStamp,      // Nanoseconds
        std::vector<QuicApiData> &Apis) const = 0;
};

//
// Create a new QUIC event collection.
//
IQuicEventCollection* NewQuicEventCollection();
