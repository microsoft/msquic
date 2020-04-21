/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Very Simple QUIC HTTP 1.1 GET server.

--*/

#include "InteropServer.h"

const QUIC_API_TABLE* MsQuic;
QUIC_SEC_CONFIG* SecurityConfig;
const char* RootFolderPath;
const char* UploadFolderPath;

const QUIC_BUFFER SupportedALPNs[] = {
    { sizeof("hq-27") - 1, (uint8_t*)"hq-27" },
    { sizeof("hq-25") - 1, (uint8_t*)"hq-25" }
};

void
PrintUsage()
{
    printf("interopserver is simple http 0.9/1.1 server.\n\n");

    printf("Usage:\n");
    printf("  interopserver.exe -listen:<addr or *> -root:<path>"
           " [-thumbprint:<cert_thumbprint>] [-name:<cert_name>]"
           " [-file:<cert_filepath> AND -key:<cert_key_filepath>]"
           " [-port:<####> (def:%u)]  [-retry:<0/1> (def:%u)]"
           " [-upload:<path>]\n\n",
           DEFAULT_QUIC_HTTP_SERVER_PORT, DEFAULT_QUIC_HTTP_SERVER_RETRY);

    printf("Examples:\n");
    printf("  interopserver.exe -listen:127.0.0.1 -name:localhost -port:443 -root:c:\\temp\n");
    printf("  interopserver.exe -listen:* -retry:1 -thumbprint:175342733b39d81c997817296c9b691172ca6b6e -root:c:\\temp\n");
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    if (argc < 2 ||
        GetValue(argc, argv, "help") ||
        GetValue(argc, argv, "?")) {
        PrintUsage();
        return -1;
    }

    HQUIC Registration = nullptr;
    EXIT_ON_FAILURE(MsQuicOpen(&MsQuic));
    const QUIC_REGISTRATION_CONFIG RegConfig = { "interopserver", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    EXIT_ON_FAILURE(MsQuic->RegistrationOpen(&RegConfig, &Registration));

    //
    // Optional parameters.
    //
    uint16_t LocalPort = DEFAULT_QUIC_HTTP_SERVER_PORT;
    BOOLEAN Retry = DEFAULT_QUIC_HTTP_SERVER_RETRY;
    TryGetValue(argc, argv, "port", &LocalPort);
    TryGetValue(argc, argv, "retry", &Retry);
    if (Retry) {
        EXIT_ON_FAILURE(QuicForceRetry(MsQuic, true));
        printf("Enabling forced RETRY on server.\n");
    }
    TryGetValue(argc, argv, "upload", &UploadFolderPath);

    //
    // Required parameters.
    //
    const char* ListenAddrStr = nullptr;
    QUIC_ADDR ListenAddr = { 0 };
    if (!TryGetValue(argc, argv, "listen", &ListenAddrStr) ||
        !ConvertArgToAddress(ListenAddrStr, LocalPort, &ListenAddr)) {
        printf("Missing or invalid '-listen' arg!\n");
        return -1;
    }
    if (!TryGetValue(argc, argv, "root", &RootFolderPath)) {
        printf("Missing '-root' arg!\n");
        return -1;
    }

    const char* CertThumbprint = nullptr;
    const char* CertName = nullptr;
    const char* CertFile = nullptr;
    const char* CertKeyFile = nullptr;
    if (TryGetValue(argc, argv, "thumbprint", &CertThumbprint)) {
        SecurityConfig = GetSecConfigForThumbprint(MsQuic, Registration, CertThumbprint);
        if (SecurityConfig == nullptr) {
            printf("Failed to find certificate from thumbprint:'%s'.\n", CertThumbprint);
            return -1;
        }
    } else if (TryGetValue(argc, argv, "name", &CertName)) {
        SecurityConfig = GetSecConfigForSNI(MsQuic, Registration, CertName);
        if (SecurityConfig == nullptr) {
            printf("Failed to find certificate from name:'%s'.\n", CertName);
            return -1;
        }
    } else if (TryGetValue(argc, argv, "file", &CertFile) &&
        TryGetValue(argc, argv, "key", &CertKeyFile)) {
        SecurityConfig = GetSecConfigForFile(MsQuic, Registration, CertKeyFile, CertFile);
        if (SecurityConfig == nullptr) {
            printf("Failed to find certificate from file:'%s'.\n", CertFile);
            return -1;
        }
    } else {
        printf("Missing arg loading server certificate!\n");
        return -1;
    }

    {
        HttpSession Session(Registration, SupportedALPNs, ARRAYSIZE(SupportedALPNs), &ListenAddr);
        printf("Press Enter to exit.\n\n");
        getchar();
    }

    MsQuic->SecConfigDelete(SecurityConfig);
    MsQuic->RegistrationClose(Registration);
    MsQuicClose(MsQuic);

    return 0;
}

//
// HttpRequest
//

HttpRequest::HttpRequest(HttpConnection *connection, HQUIC stream, bool Unidirectional) :
    Connection(connection), QuicStream(stream), File(nullptr),
    Shutdown(false), WriteHttp11Header(false)
{
    MsQuic->SetCallbackHandler(
        QuicStream,
        (Unidirectional) ? (void*)UnidirectionalStreamCallback : (void*)QuicCallbackHandler,
        this);
    Connection->AddRef();
}

HttpRequest::~HttpRequest()
{
    if (File) {
        fflush(File);
        fclose(File);
    }
    MsQuic->StreamClose(QuicStream);
    Connection->Release();
}

void
HttpRequest::Process()
{
    if (Shutdown) {
        return;
    }

    QUIC_BUFFER* QuicBuffer = &Buffer.QuicBuffer;

    if (QuicBuffer->Length < 5 ||
        _strnicmp((const char*)QuicBuffer->Buffer, "get ", 4) != 0) {
        printf("[%s] Invalid get\n", GetRemoteAddr(MsQuic, QuicStream).Address);
        Abort();
        return;
    }

    char* PathStart = (char*)QuicBuffer->Buffer + 4;

    char* end = strpbrk(PathStart, " \r\n");
    if (end != NULL) {
        if (*end == ' ') {
            WriteHttp11Header = true;
        }
        *end = '\0';
    }

    if (strstr(PathStart, "..") != nullptr) {
        printf("[%s] '..' found\n", GetRemoteAddr(MsQuic, QuicStream).Address);
        Abort(); // Don't allow requests with ../ in them.
        return;
    }

    char fullFilePath[256];
    strcpy(fullFilePath, RootFolderPath);
    if (strcmp("/", PathStart) == 0) {
        strcat(fullFilePath, "/index.html");
    } else {
        strcat(fullFilePath, PathStart);
    }

    printf("[%s] GET '%s'\n", GetRemoteAddr(MsQuic, QuicStream).Address, PathStart);
    File = fopen(fullFilePath, "rb"); // In case of failure, SendData still works.

    SendData();
}

void
HttpRequest::SendData()
{
    if (Shutdown) {
        return;
    }

    Buffer.Reset();

    if (File) {
        if (WriteHttp11Header) {
            const char Http11ResponseHeaders[] = "HTTP/1.1 200 OK\r\nConnection: Close\r\n\r\n";
            Buffer.Write(Http11ResponseHeaders, sizeof(Http11ResponseHeaders));
            WriteHttp11Header = false;
        }

        while (!Buffer.IsFull()) {
            size_t BytesAvail = IO_SIZE - Buffer.QuicBuffer.Length;
            size_t BytesRead =
                fread(
                    Buffer.RawBuffer + Buffer.QuicBuffer.Length,
                    BytesAvail,
                    1,
                    File);
            Buffer.QuicBuffer.Length += (uint32_t)BytesRead;
            if (BytesAvail != BytesRead) {
                Buffer.Flags |= QUIC_SEND_FLAG_FIN;
                Shutdown = true;
                break;
            }
        }

    } else {
        const char BadRequestBuffer11[] = "HTTP/1.1 400 BAD REQUEST\r\nConnection: Close\r\n\r\n";
        const char BadRequestBuffer[] = "BAD REQUEST";
        const char *ResponseBuffer = BadRequestBuffer;
        uint32_t ResponseBufferSize = sizeof(BadRequestBuffer) - 1;

        if (WriteHttp11Header) {
            ResponseBuffer = BadRequestBuffer11;
            ResponseBufferSize = sizeof(BadRequestBuffer11) - 1;
            WriteHttp11Header = false;
        }

        Buffer.Write(ResponseBuffer, ResponseBufferSize);
        Buffer.Flags |= QUIC_SEND_FLAG_FIN;
        Shutdown = true;
    }

    if (QUIC_FAILED(
        MsQuic->StreamSend(
            QuicStream,
            &Buffer.QuicBuffer,
            1,
            Buffer.Flags,
            this))) {
        printf("[%s] Send failed\n", GetRemoteAddr(MsQuic, QuicStream).Address);
        Abort();
    }
}

void
HttpRequest::ReceiveData(
    _In_ const QUIC_BUFFER* Buffers,
    _In_ uint32_t BufferCount
    )
{
    if (File != nullptr) {
        //
        // Write to the file
        //
        for(uint32_t i = 0; i < BufferCount; ++i) {
            if (fwrite(Buffers[i].Buffer, 1, Buffers[i].Length, File) < Buffers[i].Length) {
                printf("[%s] Failed to write file\n", GetRemoteAddr(MsQuic, QuicStream).Address);
                Abort(QUIC_STATUS_INTERNAL_ERROR);
                return;
            }
        }
    } else {
        //
        // Parse the buffer for POST header
        //
        const QUIC_BUFFER* FirstBuffer = Buffers;

        if (UploadFolderPath == nullptr) {
            printf("[%s] Server not configured for POST!\n", GetRemoteAddr(MsQuic, QuicStream).Address);
            Abort(QUIC_STATUS_NOT_SUPPORTED);
            return;
        }

        if (FirstBuffer->Length < 5 ||
            _strnicmp((const char*)FirstBuffer->Buffer, "post ", 5) != 0) {
            printf("[%s] Invalid post\n", GetRemoteAddr(MsQuic, QuicStream).Address);
            Abort(QUIC_STATUS_INVALID_PARAMETER);
            return;
        }

        char* FileName = (char*)FirstBuffer->Buffer + 5;

        char* end = strstr(FileName, " \r\n");
        if (end != nullptr) {
            //
            // We shouldn't be writing to the buffer. Don't imitate this.
            //
            *end = '\0';
        } else {
            printf("[%s] Invalid post\n", GetRemoteAddr(MsQuic, QuicStream).Address);
            Abort(QUIC_STATUS_INVALID_PARAMETER);
            return;
        }

        if (strstr(FileName, "..") != nullptr) {
            printf("[%s] '..' found\n", GetRemoteAddr(MsQuic, QuicStream).Address);
            Abort(QUIC_STATUS_INVALID_PARAMETER); // Don't allow requests with ../ in them.
            return;
        }

        char fullFilePath[256];
        if (snprintf(fullFilePath, sizeof(fullFilePath), "%s/%s", UploadFolderPath, FileName) < 0) {
            printf("[%s] invalid path\n", GetRemoteAddr(MsQuic, QuicStream).Address);
            Abort(QUIC_STATUS_INTERNAL_ERROR);
            return;
        }

        printf("[%s] POST '%s'\n", GetRemoteAddr(MsQuic, QuicStream).Address, FileName);
        File = fopen(fullFilePath, "wb");

        //
        // Write data received, if available.
        //
        uint32_t DataLength = FirstBuffer->Length - (5 + (uint32_t)(end - FileName) + 3);
        if (DataLength > 0) {
            if (fwrite(FirstBuffer->Buffer, 1, DataLength, File) < DataLength) {
                printf("[%s] Failed to write file: %s\n", GetRemoteAddr(MsQuic, QuicStream).Address, fullFilePath);
                Abort(QUIC_STATUS_INTERNAL_ERROR);
                return;
            }
        }

        if (BufferCount > 1) {
            //
            // Write the rest of the data in other buffers
            //
            ReceiveData(Buffers + 1, BufferCount - 1);
        }
    }
}

QUIC_STATUS
QUIC_API
HttpRequest::QuicCallbackHandler(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    auto pThis = (HttpRequest*)Context;
    auto Buffer = &pThis->Buffer;

    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        if (!Buffer->HasRoom(Event->RECEIVE.TotalBufferLength)) {
            printf("[%s] No room for recv\n", GetRemoteAddr(MsQuic, Stream).Address);
            pThis->Abort();
        } else {
            for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                Buffer->Write(
                    Event->RECEIVE.Buffers[i].Buffer,
                    Event->RECEIVE.Buffers[i].Length);
            }
            Buffer->QuicBuffer.Buffer[Buffer->QuicBuffer.Length] = 0;
        }
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        pThis->SendData();
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        pThis->Process();
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        printf("[%s] Peer abort\n", GetRemoteAddr(MsQuic, Stream).Address);
        pThis->Abort();
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        delete pThis;
        break;
    }

    return QUIC_STATUS_SUCCESS;
}


_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
HttpRequest::UnidirectionalStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    auto pThis = (HttpRequest*)Context;
    if (Event->Type == QUIC_STREAM_EVENT_RECEIVE) {
        printf("Receiving data!\n");
        pThis->ReceiveData(Event->RECEIVE.Buffers, Event->RECEIVE.BufferCount);
        Event->RECEIVE.TotalBufferLength = 0; // Consume all data
    } else if (Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) {
        //
        // Don't care about anything else on the stream except closing it in
        // resposne to shutdown complete.
        //
        delete pThis;
    }
    return QUIC_STATUS_SUCCESS;
}
