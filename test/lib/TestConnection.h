/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic Connection Wrapper

--*/

class TestConnection;

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
    bool UseSendBuffer      : 1;

    bool ExpectedResumed    : 1;
    QUIC_STATUS ExpectedTransportCloseStatus;
    QUIC_UINT62 ExpectedPeerCloseErrorCode;

    QUIC_STATUS TransportCloseStatus;
    QUIC_UINT62 PeerCloseErrorCode;

    QUIC_EVENT EventConnectionComplete;
    QUIC_EVENT EventPeerClosed;
    QUIC_EVENT EventShutdownComplete;

    NEW_STREAM_CALLBACK_HANDLER NewStreamCallback;
    CONN_SHUTDOWN_COMPLETE_CALLBACK_HANDLER ShutdownCompleteCallback;

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
        _In_ HQUIC Handle, // Client: SessionHandle; Server:ConnectionHandle
        _In_ NEW_STREAM_CALLBACK_HANDLER NewStreamCallbackHandler,
        _In_ bool Server,
        _In_ bool AutoDelete = false,
        _In_ bool UseSendBuffer = true
        );

    ~TestConnection();

    bool IsValid() const { return QuicConnection != nullptr; }

    QUIC_STATUS
    Start(
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
        _In_ QUIC_STREAM_OPEN_FLAGS Flags
        );

    bool WaitForConnectionComplete();

    bool WaitForZeroRttTicket();

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

    QUIC_STATUS GetTransportCloseStatus() const { return TransportCloseStatus; };
    QUIC_UINT62 GetPeerCloseErrorCode() const { return PeerCloseErrorCode; };

    QUIC_STATUS GetExpectedTransportCloseStatus() const { return ExpectedTransportCloseStatus; };
    void SetExpectedTransportCloseStatus(QUIC_STATUS Status) { ExpectedTransportCloseStatus = Status; }

    QUIC_UINT62 GetExpectedPeerCloseErrorCode() const { return ExpectedPeerCloseErrorCode; };
    void SetExpectedPeerCloseErrorCode(QUIC_UINT62 ErrorCode) { ExpectedPeerCloseErrorCode = ErrorCode; }

    //
    // Parameters
    //

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

    QUIC_STATISTICS GetStatistics();

    uint32_t GetCertValidationFlags();
    QUIC_STATUS SetCertValidationFlags(uint32_t value);

    uint32_t GetKeepAlive();                    // milliseconds
    QUIC_STATUS SetKeepAlive(uint32_t value);   // milliseconds

    bool GetShareUdpBinding();
    QUIC_STATUS SetShareUdpBinding(bool value);

    QUIC_STREAM_SCHEDULING_SCHEME GetPriorityScheme();
    QUIC_STATUS SetPriorityScheme(QUIC_STREAM_SCHEDULING_SCHEME value);

    QUIC_STATUS SetSecurityConfig(QUIC_SEC_CONFIG* value);

    bool HasNewZeroRttTicket();
};
