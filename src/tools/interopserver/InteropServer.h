/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define _CRT_SECURE_NO_WARNINGS 1

#include <msquichelper.h>

extern const QUIC_API_TABLE* MsQuic;
extern HQUIC Configuration;

const QUIC_BUFFER QuackBuffer = { sizeof("quack") - 1, (uint8_t*)"quack" };
const QUIC_BUFFER QuackAckBuffer = { sizeof("quack-ack") - 1, (uint8_t*)"quack-ack" };

//
// The default port used for connecting with QuicHttpServer.
//
#define DEFAULT_QUIC_HTTP_SERVER_PORT 4433

//
// The default retry option for QuicHttpServer.
//
#define DEFAULT_QUIC_HTTP_SERVER_RETRY FALSE

//
// The maximum requests the server accepts per connection.
//
#define MAX_HTTP_REQUESTS_PER_CONNECTION 100

//
// The send IO size to use.
//
#define IO_SIZE 64 * 1024

//
// Siduck error code for invalid payload.
//
#define SIDUCK_ONLY_QUACKS_ECHO 0x101

//
// Exits if there is a failure.
//
#define EXIT_ON_FAILURE(x) do { \
    auto _Status = x; \
    if (QUIC_FAILED(_Status)) { \
       printf("%s:%d %s failed!\n", __FILE__, __LINE__, #x); \
       exit(1); \
    } \
} while (0);

struct HttpSendBuffer {
    QUIC_SEND_FLAGS Flags;
    QUIC_BUFFER QuicBuffer;
    uint8_t RawBuffer[IO_SIZE];
    HttpSendBuffer() {
        Flags = QUIC_SEND_FLAG_NONE;
        QuicBuffer.Buffer = RawBuffer;
        QuicBuffer.Length = 0;
    }
    bool IsFull() const { return QuicBuffer.Length == IO_SIZE; }
    bool HasRoom(uint64_t Length) const { return Length + QuicBuffer.Length < IO_SIZE; }
    void Write(const void* Buffer, uint32_t Length) {
        memcpy(QuicBuffer.Buffer + QuicBuffer.Length, Buffer, Length);
        QuicBuffer.Length += Length;
    }
    void Reset() {
        QuicBuffer.Length = 0;
    }
};

struct HttpConnection;

enum HttpRequestErrorCodes {
    HttpRequestNoError,
    HttpRequestNotGet,
    HttpRequestFoundDots,
    HttpRequestGetTooBig,
    HttpRequestSendFailed,
    HttpRequestRecvNoRoom,
    HttpRequestPeerAbort,
    HttpRequestExtraRecv,
};

struct HttpRequest {
    HttpRequest(HttpConnection *connection, HQUIC stream, bool Unidirectional);
private:
    HttpConnection *Connection;
    HQUIC QuicStream;
    FILE* File;
    HttpSendBuffer Buffer;
    bool Shutdown;
    bool WriteHttp11Header;
private:
    ~HttpRequest();
    void Abort(HttpRequestErrorCodes ErrorCode) {
        Shutdown = true;
        MsQuic->StreamShutdown(
            QuicStream,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
            ErrorCode);
    }
    void Process();
    void SendData();
    bool ReceiveUniDiData(
        _In_ const QUIC_BUFFER* Buffers,
        _In_ uint32_t BufferCount
        );
    static
    QUIC_STATUS
    QUIC_API
    QuicBidiCallbackHandler(
        _In_ HQUIC Stream,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event
        );
    static
    QUIC_STATUS
    QUIC_API
    QuicUnidiCallbackHandler(
        _In_ HQUIC Stream,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event
        );
};

struct HttpConnection {
    HttpConnection(HQUIC connection) :
        QuicConnection(connection), RefCount(1) {
        MsQuic->SetCallbackHandler(QuicConnection, (void*)QuicCallbackHandler, this);
    }
    ~HttpConnection() {
        MsQuic->ConnectionClose(QuicConnection);
    }
    void AddRef() {
        InterlockedIncrement(&RefCount);
    }
    void Release() {
        if (InterlockedDecrement(&RefCount) == 0) {
            delete this;
        }
    }
private:
    HQUIC QuicConnection;
    long RefCount;
private:
    static
    QUIC_STATUS
    QUIC_API
    QuicCallbackHandler(
        _In_ HQUIC,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        ) {
        HttpConnection *pThis = (HttpConnection*)Context;
        switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            MsQuic->ConnectionSendResumptionTicket(pThis->QuicConnection, QUIC_SEND_RESUMPTION_FLAG_FINAL, 0, nullptr);
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            new HttpRequest(
                pThis,
                Event->PEER_STREAM_STARTED.Stream,
                Event->PEER_STREAM_STARTED.Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            pThis->Release();
            break;
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }
};

struct DatagramConnection {
    DatagramConnection(HQUIC connection) :
        QuicConnection(connection) {
        BOOLEAN EnableDatagrams = TRUE;
        MsQuic->SetParam(
            QuicConnection,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,
            sizeof(EnableDatagrams),
            &EnableDatagrams);
        MsQuic->SetCallbackHandler(QuicConnection, (void*)QuicCallbackHandler, this);
    }
    ~DatagramConnection() {
        MsQuic->ConnectionClose(QuicConnection);
    }
private:
    HQUIC QuicConnection;
private:
    static
    QUIC_STATUS
    QUIC_API
    QuicCallbackHandler(
        _In_ HQUIC,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        ) {
        DatagramConnection *pThis = (DatagramConnection*)Context;
        switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            MsQuic->ConnectionSendResumptionTicket(pThis->QuicConnection, QUIC_SEND_RESUMPTION_FLAG_FINAL, 0, nullptr);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            delete pThis;
            break;
        case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
            if (Event->DATAGRAM_RECEIVED.Buffer->Length == QuackBuffer.Length &&
                !memcmp(Event->DATAGRAM_RECEIVED.Buffer->Buffer, QuackBuffer.Buffer, QuackBuffer.Length)) {
                MsQuic->DatagramSend(pThis->QuicConnection, &QuackAckBuffer, 1, QUIC_SEND_FLAG_NONE, nullptr);
            } else {
                MsQuic->ConnectionShutdown(pThis->QuicConnection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, SIDUCK_ONLY_QUACKS_ECHO);
            }
            break;
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }
};

struct HttpServer {
    HttpServer(
        _In_ HQUIC Registration,
        _In_reads_(AlpnBufferCount) _Pre_defensive_
            const QUIC_BUFFER* const AlpnBuffers,
        _In_range_(>, 0) uint32_t AlpnBufferCount,
        const QUIC_ADDR* LocalAddress) {

        EXIT_ON_FAILURE(
            MsQuic->ListenerOpen(
                Registration,
                QuicCallbackHandler,
                this,
                &QuicListener));
        EXIT_ON_FAILURE(
            MsQuic->ListenerStart(
                QuicListener,
                AlpnBuffers,
                AlpnBufferCount,
                LocalAddress));
    }
    ~HttpServer() {
        MsQuic->ListenerClose(QuicListener);
    }
private:
    HQUIC QuicListener;
private:
    static
    QUIC_STATUS
    QUIC_API
    QuicCallbackHandler(
        _In_ HQUIC,
        _In_opt_ void*,
        _Inout_ QUIC_LISTENER_EVENT* Event
        ) {
        if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
            if (Event->NEW_CONNECTION.Info->NegotiatedAlpnLength >= 6 &&
                !memcmp(Event->NEW_CONNECTION.Info->NegotiatedAlpn, "siduck", 6)) {
                new DatagramConnection(Event->NEW_CONNECTION.Connection);
            } else {
                new HttpConnection(Event->NEW_CONNECTION.Connection);
            }
            return MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
        }
        return QUIC_STATUS_NOT_SUPPORTED;
    }
};
