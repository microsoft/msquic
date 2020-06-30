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

struct PingConnection {

    PingTracker* Tracker;
    HQUIC QuicConnection;
    bool DumpResumption;
    bool IsServer;

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
    // Constructor for creating a new connection.
    //
    PingConnection(
        _In_ PingTracker* Tracker,
        _In_ HQUIC Session,
        _In_ bool DumpResumption
        );

    //
    // Constructor for incoming connection with tracker.
    //
    PingConnection(
        _In_ PingTracker* Tracker,
        _In_ HQUIC Connection
        );

    //
    // Destructor. Closes the associated connection.
    //
    ~PingConnection();

    //
    // Initializes all the QUIC parameters on the connection.
    //
    bool Initialize(bool IsServer);

    //
    // Starts the connection handshake to the server.
    //
    bool Connect();

    //
    // Called by the child stream when it's done cleaning up.
    //
    void
    OnPingStreamShutdownComplete(
        _In_ PingStream *Stream
        );

private:

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
