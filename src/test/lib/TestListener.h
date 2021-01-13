/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic Listener Wrapper

--*/

class TestListener;

//
// Callback for processing incoming connections. Returns true if the connection
// is accepted.
//
typedef
_Function_class_(NEW_CONNECTION_CALLBACK)
bool
(NEW_CONNECTION_CALLBACK)(
    _In_ TestListener* Listener,
    _In_ HQUIC ConnectionHandle
    );

typedef NEW_CONNECTION_CALLBACK *NEW_CONNECTION_CALLBACK_HANDLER;

//
// A C++ Wrapper for the MsQuic Listener handle.
//
class TestListener
{
    HQUIC QuicListener;
    HQUIC QuicConfiguration;

    bool FilterConnections : 1;
    bool HasRandomLoss     : 1;

    NEW_CONNECTION_CALLBACK_HANDLER NewConnectionCallback;

    QUIC_STATUS
    HandleListenerEvent(
        _Inout_ QUIC_LISTENER_EVENT* Event
        );

    _IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(QUIC_LISTENER_CALLBACK)
    static
    QUIC_STATUS
    QUIC_API
    QuicListenerHandler(
        _In_ HQUIC /* QuicListener */,
        _In_opt_ void* Context,
        _Inout_ QUIC_LISTENER_EVENT* Event
        )
    {
        TestListener* Listener = (TestListener*)Context;
        return Listener->HandleListenerEvent(Event);
    }

public:

    TestListener(
        _In_ HQUIC Registration,
        _In_ NEW_CONNECTION_CALLBACK_HANDLER NewConnectionCallbackHandler,
        _In_opt_ HQUIC Configuration
        );

    ~TestListener();

    bool IsValid() const { return QuicListener != nullptr; }

    QUIC_STATUS
    Start(
        _In_reads_(AlpnBufferCount) _Pre_defensive_
            const QUIC_BUFFER* const AlpnBuffers,
        _In_range_(>, 0) uint32_t AlpnBufferCount,
        _In_opt_ const QUIC_ADDR* LocalAddress = nullptr
        );

    QUIC_STATUS
    Start(
        _In_ const MsQuicAlpn& Alpn,
        _In_opt_ const QUIC_ADDR* LocalAddress = nullptr
        )
    {
        return Start(Alpn, Alpn.Length(), LocalAddress);
    }

    void Stop();

    //
    // State
    //

    void* Context; // Not used internally.

    bool GetFilterConnections() const { return FilterConnections; }
    void SetFilterConnections(bool value) { FilterConnections = value; }


    //
    // Parameters
    //

    QUIC_STATUS GetLocalAddr(_Out_ QuicAddr &localAddr);
    QUIC_STATUS GetStatistics(_Out_ QUIC_LISTENER_STATISTICS &stats);

    bool GetHasRandomLoss() const { return HasRandomLoss; }
    void SetHasRandomLoss(bool Value) { HasRandomLoss = Value; }
};
