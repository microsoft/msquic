/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic Stream Wrapper

--*/

class TestStream;

//
// The maximum size of a send request. An arbitrary size to test packetization/framing.
//
const size_t MaxSendLength = 9929;

//
// The maximum number of outstanding send requests.
//
const size_t MaxSendRequestQueue = 16;

//
// The maximum number of QUIC_BUFFER per send request.
//
const uint32_t MaxSendBuffers = 2;

//
// Callback for handling stream shutdown completion.
//
typedef
_Function_class_(STREAM_SHUTDOWN_CALLBACK)
void
(STREAM_SHUTDOWN_CALLBACK)(
    _In_ TestStream* Stream
    );

typedef STREAM_SHUTDOWN_CALLBACK *STREAM_SHUTDOWN_CALLBACK_HANDLER;

//
// Helper class for managing dynamic send buffers.
//
struct QuicSendBuffer
{
    uint32_t BufferCount;
    QUIC_BUFFER* Buffers;

    QuicSendBuffer(
        uint32_t bufferCount,
        uint32_t bufferSize
        ) :
        BufferCount(bufferCount),
        Buffers(new(std::nothrow) QUIC_BUFFER[bufferCount])
    {
        for (uint32_t i = 0; i < BufferCount; ++i) {
            this->Buffers[i].Buffer = bufferSize == 0 ? nullptr : new(std::nothrow) uint8_t[bufferSize];
            this->Buffers[i].Length = bufferSize;
            if (this->Buffers[i].Length != 0) {
                CxPlatZeroMemory(this->Buffers[i].Buffer, this->Buffers[i].Length);
            }
        }
    }

    QuicSendBuffer(
        uint32_t bufferSize,
        const uint8_t * buffer
        ) :
        BufferCount(1),
        Buffers(new(std::nothrow) QUIC_BUFFER[1])
    {
        this->Buffers[0].Buffer = bufferSize == 0 ? nullptr : new(std::nothrow) uint8_t[bufferSize];
        if (bufferSize != 0) {
            memcpy((uint8_t*)this->Buffers[0].Buffer, buffer, bufferSize);
        }
        this->Buffers[0].Length = bufferSize;
    }

    //
    // Destructor
    //
    ~QuicSendBuffer()
    {
        for (uint32_t i = 0; i < BufferCount; ++i) {
            delete [] this->Buffers[i].Buffer;
        }
        delete [] this->Buffers;
    }
};

//
// A C++ Wrapper for the MsQuic Stream handle.
//
class TestStream
{
    HQUIC QuicStream;

    bool IsUnidirectional   : 1;
    bool IsPingSource       : 1;
    bool UsedZeroRtt        : 1;
    bool AllDataSent        : 1;
    bool AllDataReceived    : 1;
    bool SendShutdown       : 1;
    bool RecvShutdown       : 1;
    bool IsShutdown         : 1;

    bool ConnectionShutdown       : 1;
    bool ConnectionShutdownByApp  : 1;
    bool ConnectionClosedRemotely : 1;
    QUIC_UINT62 ConnectionErrorCode;
    QUIC_STATUS ConnectionCloseStatus;

    volatile int64_t BytesToSend;
    volatile long OutstandingSendRequestCount;
    uint64_t BytesReceived;

    CXPLAT_EVENT EventSendShutdownComplete;
    CXPLAT_EVENT EventRecvShutdownComplete;

    STREAM_SHUTDOWN_CALLBACK_HANDLER StreamShutdownCallback;

    TestStream(
        _In_ HQUIC Handle,
        _In_opt_ STREAM_SHUTDOWN_CALLBACK_HANDLER StreamShutdownHandler,
        _In_ bool IsUnidirectional,
        _In_ bool IsPingSource
        );

    QUIC_STATUS
    HandleStreamEvent(
        _Inout_ QUIC_STREAM_EVENT* Event
        );

    void
    HandleStreamRecv(
        _In_reads_(Length)
            const uint8_t * Buffer,
        _In_ uint32_t Length,
        _In_ QUIC_RECEIVE_FLAGS Flags
        );

    void
    HandleStreamSendComplete(
        _In_ bool Canceled,
        _In_ QuicSendBuffer* SendBuffer
        );

    _IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK)
    static
    QUIC_STATUS
    QUIC_API
    QuicStreamHandler(
        _In_ HQUIC /* QuicStream */,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event
        )
    {
        TestStream* Stream = (TestStream*)Context;
        return Stream->HandleStreamEvent(Event);
    }

public:

    ~TestStream();

    bool IsValid() const { return QuicStream != nullptr; }

    static
    TestStream*
    FromStreamHandle(
        _In_ HQUIC QuicStreamHandle,
        _In_opt_ STREAM_SHUTDOWN_CALLBACK_HANDLER StreamShutdownHandler,
        _In_ QUIC_STREAM_OPEN_FLAGS Flags
        );

    static
    TestStream*
    FromConnectionHandle(
        _In_ HQUIC QuicConnectionHandle,
        _In_opt_ STREAM_SHUTDOWN_CALLBACK_HANDLER StreamShutdownHandler,
        _In_ QUIC_STREAM_OPEN_FLAGS Flags
        );

    QUIC_STATUS
    Shutdown(
        _In_ QUIC_STREAM_SHUTDOWN_FLAGS Flags,
        _In_ QUIC_UINT62 ErrorCode
        );

    QUIC_STATUS
    Start(
        _In_ QUIC_STREAM_START_FLAGS Flags
        );

    bool
    StartPing(
        _In_ uint64_t PayloadLength,
        _In_ bool SendFin = true
        );

    bool WaitForSendShutdownComplete();

    bool WaitForRecvShutdownComplete();

    //
    // State
    //

    void* Context; // Not used internally.

    bool GetIsUnidirectional() const { return IsUnidirectional; }
    bool GetIsPingSource() const { return IsPingSource; }
    bool GetUsedZeroRtt() const { return UsedZeroRtt; }
    bool GetAllDataSent() const { return AllDataSent; }
    bool GetAllDataReceived() const { return AllDataReceived; }
    bool GetSendShutdown() const { return SendShutdown; }
    bool GetIsShutdown() const { return IsShutdown; }

    bool GetConnectionShutdown() const { return ConnectionShutdown; }
    bool GetShutdownByApp() const { return ConnectionShutdownByApp; }
    bool GetClosedRemotely() const { return ConnectionClosedRemotely; }
    QUIC_UINT62 GetConnectionErrorCode() const { return ConnectionErrorCode; }
    QUIC_STATUS GetConnectionCloseStatus() const { return ConnectionCloseStatus; }

    uint64_t GetBytesToSend() const { return (uint64_t)BytesToSend; }
    uint32_t GetOutstandingSendRequestCount() const { return OutstandingSendRequestCount; };
    uint64_t GetBytesReceived() const{ return BytesReceived; }

    //
    // Parameters
    //

    uint64_t GetStreamID();

    QUIC_STATUS SetReceiveEnabled(bool value);
};
