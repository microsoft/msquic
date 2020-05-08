/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Ping Stream declaration. Definites the functions and variables used
    in the PingStream class.

--*/

struct PingConnection;

enum PingStreamMode {
    UniSendMode,
    UniRecvMode,
    BidiSendMode,
    BidiEchoMode
};

struct PingStream {

    PingConnection *Connection;
    HQUIC QuicStream;
    PingStreamMode Mode;
    bool Aborted;

    uint64_t StartTime;
    uint64_t CompleteTime;

    uint64_t BytesSent;
    uint64_t BytesCompleted;
    uint64_t BytesReceived;

    //
    // Constructor for creating a new stream.
    //
    PingStream(
        _In_ PingConnection *connection,
        _In_ PingStreamMode mode
        );

    //
    // Constructor for incoming stream.
    //
    PingStream(
        _In_ PingConnection *connection,
        _In_ HQUIC stream,
        _In_ PingStreamMode modes
        );

    //
    // Destructor. Closes the associated stream.
    //
    ~PingStream();

    //
    // Creates the underlying stream and starts sending.
    //
    bool
    Start();

private:

    bool
    QueueSendRequest(
        PingSendRequest* SendRequest
        );

    bool
    StartSend();

    void
    ProcessEvent(
        _Inout_ QUIC_STREAM_EVENT* Event
        );

    static
    QUIC_STATUS
    QUIC_API
    QuicCallbackHandler(
        _In_ HQUIC Stream,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event
        );
};
