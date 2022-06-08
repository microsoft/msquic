/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic Connection Wrapper

--*/

class TestConnection;

enum NEW_STREAM_START_TYPE {
    NEW_STREAM_START_NONE,      // Dont' start
    NEW_STREAM_START_SYNC,      // Start synchronously
    NEW_STREAM_START_ASYNC      // Start asynchronously
};

//
// Callback for processing peer created streams.
//
typedef
_Function_class_(NEW_STREAM_CALLBACK)
void
(NEW_STREAM_CALLBACK)(
    _In_ TestConnection* Connection,
    _In_ HQUIC StreamHandle,
    _In_ QUIC_STREAM_OPEN_FLAGS Flags
    );

typedef NEW_STREAM_CALLBACK *NEW_STREAM_CALLBACK_HANDLER;

//
// Callback for processing shutdown complete.
//
typedef
_Function_class_(CONN_SHUTDOWN_COMPLETE_CALLBACK)
void
(CONN_SHUTDOWN_COMPLETE_CALLBACK)(
    _In_ TestConnection* Connection
    );

typedef CONN_SHUTDOWN_COMPLETE_CALLBACK *CONN_SHUTDOWN_COMPLETE_CALLBACK_HANDLER;

//
// A C++ Wrapper for the MsQuic Connection handle.
//
class TestConnection
{
    HQUIC QuicConnection;

    bool IsServer           : 1;
    bool IsStarted          : 1;
    bool IsConnected        : 1;
    bool Resumed            : 1;
    bool PeerAddrChanged    : 1;
    bool PeerClosed         : 1;
    bool TransportClosed    : 1;
    bool IsShutdown         : 1;
    bool ShutdownTimedOut   : 1;
    bool AutoDelete         : 1;
    bool HasRandomLoss      : 1;
    bool AsyncCustomValidation : 1;
    bool CustomValidationResultSet : 1;

    bool ExpectedResumed    : 1;
    QUIC_STATUS ExpectedTransportCloseStatus;
    QUIC_UINT62 ExpectedPeerCloseErrorCode;
    QUIC_STATUS ExpectedClientCertValidationResult;
    bool ExpectedCustomValidationResult;
    QUIC_STATUS PeerCertEventReturnStatus;

    QUIC_STATUS TransportCloseStatus;
    QUIC_UINT62 PeerCloseErrorCode;

    CXPLAT_EVENT EventConnectionComplete;
    CXPLAT_EVENT EventPeerClosed;
    CXPLAT_EVENT EventShutdownComplete;
    CXPLAT_EVENT EventResumptionTicketReceived;
    CXPLAT_EVENT* EventDeleted;

    NEW_STREAM_CALLBACK_HANDLER NewStreamCallback;
    CONN_SHUTDOWN_COMPLETE_CALLBACK_HANDLER ShutdownCompleteCallback;

    QUIC_BUFFER* ResumptionTicket {nullptr};

    uint32_t DatagramsSent;
    uint32_t DatagramsCanceled;
    uint32_t DatagramsSuspectLost;
    uint32_t DatagramsLost;
    uint32_t DatagramsAcknowledged;

    QUIC_STATUS
    HandleConnectionEvent(
        _Inout_ QUIC_CONNECTION_EVENT* Event
        );

    _IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK)
    static
    QUIC_STATUS
    QUIC_API
    QuicConnectionHandler(
        _In_ HQUIC /* QuicConnection */,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        )
    {
        TestConnection* Connection = (TestConnection*)Context;
        return Connection->HandleConnectionEvent(Event);
    }

public:

    TestConnection(
        _In_ HQUIC Handle, // Server:ConnectionHandle
        _In_opt_ NEW_STREAM_CALLBACK_HANDLER NewStreamCallbackHandler = nullptr
        );

    TestConnection(
        _In_ MsQuicRegistration& Registration,
        _In_opt_ NEW_STREAM_CALLBACK_HANDLER NewStreamCallbackHandler = nullptr
        );

    ~TestConnection();

    bool IsValid() const { return QuicConnection != nullptr; }

    void SetAutoDelete() { AutoDelete = true; }

    void SetDeletedEvent(CXPLAT_EVENT* Event) { EventDeleted = Event; }

    QUIC_STATUS
    Start(
        _In_ HQUIC Configuration,
        _In_ QUIC_ADDRESS_FAMILY Family,
        _In_opt_z_ const char* ServerName,
        _In_ uint16_t ServerPort // Host byte order
        );

    void
    Shutdown(
        _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
        _In_ QUIC_UINT62 ErrorCode
        );

    TestStream*
    NewStream(
        _In_opt_ STREAM_SHUTDOWN_CALLBACK_HANDLER StreamShutdownHandler,
        _In_ QUIC_STREAM_OPEN_FLAGS Flags,
        _In_ NEW_STREAM_START_TYPE StartType = NEW_STREAM_START_ASYNC
        );

    uint32_t GetWaitTimeout() const {
        uint32_t WaitTime = TestWaitTimeout;
        if (HasRandomLoss) {
            WaitTime *= 20; // TODO - Enough?
        }
        return WaitTime;
    }

    bool WaitForConnectionComplete();

    QUIC_BUFFER* WaitForResumptionTicket();

    bool WaitForShutdownComplete();

    bool WaitForPeerClose();

    void SetShutdownCompleteCallback(CONN_SHUTDOWN_COMPLETE_CALLBACK_HANDLER Handler) {
        ShutdownCompleteCallback = Handler;
    }

    //
    // State
    //

    void* Context; // Not used internally.

    HQUIC GetConnection() { return QuicConnection; }
    bool GetIsServer() const { return IsServer; }
    bool GetIsStarted() const { return IsStarted; }
    bool GetIsConnected() const { return IsConnected; }
    bool GetResumed() const { return Resumed; }
    bool GetPeerAddrChanged() const { return PeerAddrChanged; }
    bool GetPeerClosed() const { return PeerClosed; }
    bool GetTransportClosed() const { return TransportClosed; }
    bool GetIsShutdown() const { return IsShutdown; }
    bool GetShutdownTimedOut() const { return ShutdownTimedOut; }

    bool GetExpectedResumed() const { return ExpectedResumed; };
    void SetExpectedResumed(bool Value) { ExpectedResumed = Value; }

    bool GetHasRandomLoss() const { return HasRandomLoss; }
    void SetHasRandomLoss(bool Value) { HasRandomLoss = Value; }

    QUIC_STATUS GetTransportCloseStatus() const { return TransportCloseStatus; };
    QUIC_UINT62 GetPeerCloseErrorCode() const { return PeerCloseErrorCode; };

    QUIC_STATUS GetExpectedTransportCloseStatus() const { return ExpectedTransportCloseStatus; };
    void SetExpectedTransportCloseStatus(QUIC_STATUS Status) { ExpectedTransportCloseStatus = Status; }

    QUIC_UINT62 GetExpectedPeerCloseErrorCode() const { return ExpectedPeerCloseErrorCode; };
    void SetExpectedPeerCloseErrorCode(QUIC_UINT62 ErrorCode) { ExpectedPeerCloseErrorCode = ErrorCode; }

    QUIC_UINT62 GetExpectedCustomValidationResult() const { return ExpectedCustomValidationResult; };
    void SetExpectedCustomValidationResult(bool AcceptCert) { CustomValidationResultSet = true; ExpectedCustomValidationResult = AcceptCert; }
    void SetAsyncCustomValidationResult(bool Async) { AsyncCustomValidation = Async; }

    QUIC_STATUS GetExpectedClientCertValidationResult() const { return ExpectedClientCertValidationResult; }
    void SetExpectedClientCertValidationResult(QUIC_STATUS Status) { ExpectedClientCertValidationResult = Status; }

    void SetPeerCertEventReturnStatus(QUIC_STATUS Value) { PeerCertEventReturnStatus = Value; }

    uint32_t GetDatagramsSent() const { return DatagramsSent; }
    uint32_t GetDatagramsCanceled() const { return DatagramsCanceled; }
    uint32_t GetDatagramsSuspectLost() const { return DatagramsSuspectLost; }
    uint32_t GetDatagramsLost() const { return DatagramsLost; }
    uint32_t GetDatagramsAcknowledged() const { return DatagramsAcknowledged; }

    //
    // Parameters
    //

    QUIC_SETTINGS GetSettings() const;
    QUIC_STATUS SetSettings(_In_ const QUIC_SETTINGS& value);

    QUIC_STATUS ForceKeyUpdate();
    QUIC_STATUS ForceCidUpdate();

    QUIC_STATUS SetTestTransportParameter(
        _In_ const QUIC_PRIVATE_TRANSPORT_PARAMETER* TransportParameter
        );

    uint32_t GetQuicVersion();
    QUIC_STATUS SetQuicVersion(uint32_t value);

    QUIC_STATUS GetLocalAddr(_Out_ QuicAddr &localAddr);
    QUIC_STATUS SetLocalAddr(_In_ const QuicAddr &localAddr);

    QUIC_STATUS GetRemoteAddr(_Out_ QuicAddr &remoteAddr);
    QUIC_STATUS SetRemoteAddr(_In_ const QuicAddr &remoteAddr);

    uint64_t GetIdleTimeout();                          // milliseconds
    QUIC_STATUS SetIdleTimeout(uint64_t value);         // milliseconds

    uint32_t GetDisconnectTimeout();                    // milliseconds
    QUIC_STATUS SetDisconnectTimeout(uint32_t value);   // milliseconds

    uint16_t GetPeerBidiStreamCount();
    QUIC_STATUS SetPeerBidiStreamCount(uint16_t value);

    uint16_t GetPeerUnidiStreamCount();
    QUIC_STATUS SetPeerUnidiStreamCount(uint16_t value);

    uint16_t GetLocalBidiStreamCount();
    uint16_t GetLocalUnidiStreamCount();

    QUIC_STATISTICS_V2 GetStatistics();

    bool GetUseSendBuffer();
    QUIC_STATUS SetUseSendBuffer(bool value);

    uint32_t GetKeepAlive();                    // milliseconds
    QUIC_STATUS SetKeepAlive(uint32_t value);   // milliseconds

    bool GetShareUdpBinding();
    QUIC_STATUS SetShareUdpBinding(bool value);

    bool GetDatagramReceiveEnabled();
    QUIC_STATUS SetDatagramReceiveEnabled(bool value);

    bool GetDatagramSendEnabled();

    QUIC_STREAM_SCHEDULING_SCHEME GetPriorityScheme();
    QUIC_STATUS SetPriorityScheme(QUIC_STREAM_SCHEDULING_SCHEME value);

    QUIC_STATUS SetConfiguration(HQUIC value);

    QUIC_STATUS SetResumptionTicket(const QUIC_BUFFER* ResumptionTicket) const;

    QUIC_STATUS SetCustomValidationResult(bool AcceptCert);
};
