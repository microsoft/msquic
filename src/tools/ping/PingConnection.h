/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Ping Connection declaration. Defines the functions and variables used
    in the PingConnection class.

--*/

struct PingTracker {

    long RefCount;

    uint64_t BytesSent;
    uint64_t BytesReceived;

    uint64_t StartTime;
    uint64_t CompleteTime;

    QUIC_EVENT Done;

    PingTracker() :
        RefCount(1), BytesSent(0), BytesReceived(0), StartTime(0), CompleteTime(0) {
        QuicEventInitialize(&Done, FALSE, FALSE);
    }

    ~PingTracker() {
        QuicEventUninitialize(Done);
    }

    void
    Start() {
        StartTime = QuicTimeUs64();
    }

    bool
    Wait(
        uint32_t Milliseconds
        ) {
        if (InterlockedDecrement(&RefCount) == 0) {
            CompleteTime = QuicTimeUs64();
            return true;
        } else {
            return !QuicEventWaitWithTimeout(Done, Milliseconds);
        }
    }

    void
    WaitForever(
        ) {
        if (InterlockedDecrement(&RefCount) == 0) {
            CompleteTime = QuicTimeUs64();
            return;
        } else {
            QuicEventWaitForever(Done);
        }
    }

    void
    AddItem() {
        InterlockedIncrement(&RefCount);
    }

    void
    CompleteItem(
        uint64_t Sent,
        uint64_t Received
        ) {
        InterlockedExchangeAdd64((int64_t*)&BytesSent, (int64_t)Sent);
        InterlockedExchangeAdd64((int64_t*)&BytesReceived, (int64_t)Received);
        if (InterlockedDecrement(&RefCount) == 0) {
            CompleteTime = QuicTimeUs64();
            QuicEventSet(Done);
        }
    }
};

extern PingTracker Tracker;

struct PingConnection {

    HQUIC QuicConnection;
    bool DumpResumption;
    bool IsServer;
    bool ForPsci;

    uint64_t StartTime;
    uint64_t ConnectTime;
    uint64_t CompleteTime;
    bool ConnectedSuccessfully;
    bool TimedOut;

    uint64_t BytesSent;
    uint64_t BytesReceived;

    uint16_t DatagramLength;

    uint64_t DatagramsSent;
    uint64_t DatagramsAcked;
    uint64_t DatagramsLost;
    uint64_t DatagramsCancelled;

    uint64_t DatagramsReceived;
    uint64_t DatagramsJitterTotal;
    uint64_t DatagramLastTime;

    //
    // Constructor
    //
    PingConnection(
        _In_ bool IsServer = false,
        _In_ HQUIC Handle = nullptr, // Server side accepted connection
        _In_ bool DumpResumption = false,
        _In_ bool ForPsci = false
        );

    //
    // Destructor. Closes the associated connection.
    //
    ~PingConnection();

    //
    // Starts the connection handshake to the server.
    //
    bool Connect();

    //
    // Get/Set preshared connection info.
    //
    QUIC_PRESHARED_CONNECTION_INFORMATION* GetLocalPsci(uint32_t &Length);
    bool SetRemotePsci(const QUIC_PRESHARED_CONNECTION_INFORMATION* Psci);

    //
    // Called by the child stream when it's done cleaning up.
    //
    void
    OnPingStreamShutdownComplete(
        _In_ PingStream *Stream
        );

private:

    void Initialize();

    bool
    QueueDatagram(
        PingSendRequest* SendRequest
        );

    void
    ProcessEvent(
        _Inout_ QUIC_CONNECTION_EVENT* Event
        );

    static
    QUIC_STATUS
    QUIC_API
    QuicCallbackHandler(
        _In_ HQUIC Connection,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        );
};

struct PingPsciConnection {

    HQUIC QuicConnection;
    bool IsServer;

    PingConnection* NormalConnection;

    QUIC_BUFFER SendBuffer;
    QUIC_PRESHARED_CONNECTION_INFORMATION* LocalPsci;
    QUIC_PRESHARED_CONNECTION_INFORMATION* RemotePsci;

    PingPsciConnection(
        _In_ bool IsServer,
        _In_ HQUIC Handle
        );

    //
    // Destructor. Closes the associated connection.
    //
    ~PingPsciConnection();

    //
    // Starts the connection handshake to the server.
    //
    bool Connect();

    //
    // Sends the preshared connection info to the peer.
    //
    bool SendPsci(HQUIC Stream = nullptr);

private:

    QUIC_STATUS
    ProcessEvent(
        _Inout_ QUIC_CONNECTION_EVENT* Event
        );

    QUIC_STATUS
    ProcessStreamEvent(
        _In_ HQUIC Stream,
        _Inout_ QUIC_STREAM_EVENT* Event
        );

    static
    QUIC_STATUS
    QUIC_API
    QuicCallbackHandler(
        _In_ HQUIC Connection,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        );

    static
    QUIC_STATUS
    QUIC_API
    QuicStreamCallbackHandler(
        _In_ HQUIC Stream,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event
        );
};
