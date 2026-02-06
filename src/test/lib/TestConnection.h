/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic Connection Wrapper

--*/

#pragma once

#include "TestHelpers.h"
#include "TestStream.h"
#include "TestUtility.h"

class TestConnection;

enum NEW_STREAM_START_TYPE {
    NEW_STREAM_START_NONE,      // Dont' start
    NEW_STREAM_START_SYNC,      // Start synchronously
    NEW_STREAM_START_ASYNC      // Start asynchronously
};

#define DEFAULT_SSLKEYLOGFILE_NAME "sslkeylogfile.txt"

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

    // Lock protecting the TestConnection members used in the connection callback.
    mutable CxPlatLock Lock{};

    bool IsServer;
    bool IsStarted;
    bool IsConnected;
    bool Resumed;
    bool PeerAddrChanged;
    bool PeerClosed;
    bool TransportClosed;
    bool IsShutdown;
    bool ShutdownTimedOut;
    bool AutoDelete;
    bool HasRandomLoss;
    bool AsyncCustomValidation;
    bool CustomValidationResultSet;

    bool ExpectedResumed;
    QUIC_STATUS ExpectedCustomTicketValidationResult;
    QUIC_STATUS ExpectedTransportCloseStatus;
    QUIC_UINT62 ExpectedPeerCloseErrorCode;
    QUIC_STATUS ExpectedClientCertValidationResult[2];
    uint32_t ExpectedClientCertValidationResultCount;
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

    const uint8_t* NegotiatedAlpn;
    uint8_t NegotiatedAlpnLength;

    QUIC_TLS_SECRETS TlsSecrets;
    const char* SslKeyLogFileName;

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

    TestConnection(const TestConnection&) = delete;
    TestConnection& operator=(const TestConnection&) = delete;
    TestConnection(TestConnection&&) = delete;
    TestConnection& operator=(TestConnection&&) = delete;

    bool IsValid() const { return QuicConnection != nullptr; }

    void SetAutoDelete() {
        LockGuard LockScope{Lock};
        AutoDelete = true;
    }

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
        LockGuard LockScope{Lock};
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
        LockGuard LockScope{Lock};
        ShutdownCompleteCallback = Handler;
    }

    //
    // State
    //

    void* Context; // Not used internally.

    HQUIC GetConnection() { return QuicConnection; }
    bool GetIsServer() const {
        LockGuard LockScope{Lock};
        return IsServer;
    }
    bool GetIsStarted() const { return IsStarted; }
    bool GetIsConnected() const {
        LockGuard LockScope{Lock};
        return IsConnected;
    }
    bool GetResumed() const {
        LockGuard LockScope{Lock};
        return Resumed;
    }
    bool GetPeerAddrChanged() const {
        LockGuard LockScope{Lock};
        return PeerAddrChanged;
    }
    bool GetPeerClosed() const {
        LockGuard LockScope{Lock};
        return PeerClosed;
    }
    bool GetTransportClosed() const {
        LockGuard LockScope{Lock};
        return TransportClosed;
    }
    bool GetIsShutdown() const {
        LockGuard LockScope{Lock};
        return IsShutdown;
    }
    bool GetShutdownTimedOut() const {
        LockGuard LockScope{Lock};
        return ShutdownTimedOut;
    }

    bool GetExpectedResumed() const {
        LockGuard LockScope{Lock};
        return ExpectedResumed;
    };
    void SetExpectedResumed(bool Value) {
        LockGuard LockScope{Lock};
        ExpectedResumed = Value;
    }

    bool GetHasRandomLoss() const {
        LockGuard LockScope{Lock};
        return HasRandomLoss;
    }
    void SetHasRandomLoss(bool Value) {
        LockGuard LockScope{Lock};
        HasRandomLoss = Value;
    }

    QUIC_STATUS GetTransportCloseStatus() const {
        LockGuard LockScope{Lock};
        return TransportCloseStatus;
    };
    QUIC_UINT62 GetPeerCloseErrorCode() const {
        LockGuard LockScope{Lock};
        return PeerCloseErrorCode;
    };

    QUIC_STATUS GetExpectedTransportCloseStatus() const {
        LockGuard LockScope{Lock};
        return ExpectedTransportCloseStatus;
    };
    void SetExpectedTransportCloseStatus(QUIC_STATUS Status) {
        LockGuard LockScope{Lock};
        ExpectedTransportCloseStatus = Status;
    }

    QUIC_UINT62 GetExpectedPeerCloseErrorCode() const {
        LockGuard LockScope{Lock};
        return ExpectedPeerCloseErrorCode;
    };
    void SetExpectedPeerCloseErrorCode(QUIC_UINT62 ErrorCode) {
        LockGuard LockScope{Lock};
        ExpectedPeerCloseErrorCode = ErrorCode;
    }

    QUIC_UINT62 GetExpectedCustomValidationResult() const {
        LockGuard LockScope{Lock};
        return ExpectedCustomValidationResult;
    };
    void SetExpectedCustomValidationResult(bool AcceptCert) {
        LockGuard LockScope{Lock};
        CustomValidationResultSet = true;
        ExpectedCustomValidationResult = AcceptCert;
    }
    void SetAsyncCustomValidationResult(bool Async) {
        LockGuard LockScope{Lock};
        AsyncCustomValidation = Async;
    }
    void SetExpectedCustomTicketValidationResult(QUIC_STATUS Status) {
        LockGuard LockScope{Lock};
        ExpectedCustomTicketValidationResult = Status;
    }

    const QUIC_STATUS* GetExpectedClientCertValidationResult() const {
        LockGuard LockScope{Lock};
        return ExpectedClientCertValidationResult;
    }
    void AddExpectedClientCertValidationResult(QUIC_STATUS Status) {
        LockGuard LockScope{Lock};
        CXPLAT_FRE_ASSERTMSG(
            ExpectedClientCertValidationResultCount < ARRAYSIZE(ExpectedClientCertValidationResult),
            "Only two expected values supported.");
        ExpectedClientCertValidationResult[ExpectedClientCertValidationResultCount++] = Status;
    }

    void SetPeerCertEventReturnStatus(QUIC_STATUS Value) {
        LockGuard LockScope{Lock};
        PeerCertEventReturnStatus = Value;
    }

    uint32_t GetDatagramsSent() const {
        LockGuard LockScope{Lock};
        return DatagramsSent;
    }
    uint32_t GetDatagramsCanceled() const {
        LockGuard LockScope{Lock};
        return DatagramsCanceled;
    }
    uint32_t GetDatagramsSuspectLost() const {
        LockGuard LockScope{Lock};
        return DatagramsSuspectLost;
    }
    uint32_t GetDatagramsLost() const {
        LockGuard LockScope{Lock};
        return DatagramsLost;
    }
    uint32_t GetDatagramsAcknowledged() const {
        LockGuard LockScope{Lock};
        return DatagramsAcknowledged;
    }

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

    QUIC_STATUS GetOrigDestCid(_Out_ uint8_t Bytes[32], _Out_ uint32_t& Length);

    bool GetEcnEnabled();
    QUIC_STATUS SetEcnEnabled(bool value);

    uint64_t GetIdleTimeout();                          // milliseconds
    QUIC_STATUS SetIdleTimeout(uint64_t value);         // milliseconds

    uint32_t GetDisconnectTimeout();                    // milliseconds
    QUIC_STATUS SetDisconnectTimeout(uint32_t value);   // milliseconds

    uint32_t GetDestCidUpdateIdleTimeoutMs();                   // milliseconds
    QUIC_STATUS SetDestCidUpdateIdleTimeoutMs(uint32_t value);  // milliseconds

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

    QUIC_STATUS SetCustomValidationResult(bool AcceptCert, QUIC_TLS_ALERT_CODES TlsAlert = QUIC_TLS_ALERT_CODE_BAD_CERTIFICATE);

    QUIC_STATUS SetCustomTicketValidationResult(bool AcceptTicket);

    uint32_t GetDestCidUpdateCount();

    const uint8_t* GetNegotiatedAlpn() const;
    uint8_t GetNegotiatedAlpnLength() const;

    QUIC_STATUS SetTlsSecrets(QUIC_TLS_SECRETS* Secrets);

    QUIC_TLS_SECRETS GetTlsSecrets() const { return TlsSecrets; }

    void SetSslKeyLogFilePath(const char* Path = DEFAULT_SSLKEYLOGFILE_NAME) { SslKeyLogFileName = Path; }
};
