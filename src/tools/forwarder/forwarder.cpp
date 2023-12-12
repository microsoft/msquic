/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This tool creates a terminating QUIC proxy to forward all incoming traffic
    to a specified target.

--*/

#include "msquichelper.h"
#include "msquic.hpp"

const char* Alpn;
uint16_t FrontEndPort;
const char* BackEndTarget;
uint16_t BackEndPort;
QUIC_CERTIFICATE_HASH Cert;
bool BufferedMode = true;

const MsQuicApi* MsQuic;
MsQuicRegistration* Registration;
MsQuicConfiguration* FrontEndConfiguration;
MsQuicConfiguration* BackEndConfiguration;

#define USAGE \
    "Usage: quicforward <alpn> <local-port> <target-name/ip>:<target-port> <thumbprint> [0/1-buffered-mode]\n"

bool ParseArgs(int argc, char **argv) {
    if (argc < 5) {
        return false;
    }
    Alpn = argv[1];
    FrontEndPort = (uint16_t)atoi(argv[2]);
    BackEndTarget = argv[3];
    char* port = strchr(argv[3], ':');
    if (!port) {
        printf("Invalid target specified (no port).\n");
        return false;
    }
    *port = '\0'; ++port;
    BackEndPort = (uint16_t)atoi(port);
    if (DecodeHexBuffer(argv[4], sizeof(Cert.ShaHash), Cert.ShaHash) != sizeof(Cert.ShaHash)) {
        printf("Invalid thumbprint.\n");
        return false;
    }
    if (argc > 5) {
        BufferedMode = atoi(argv[5]) != 0;
    }
    return true;
}

struct ForwardedSend {
    uint64_t TotalLength;
    QUIC_BUFFER Buffers[2];
    static ForwardedSend* New(QUIC_STREAM_EVENT* Event) {
        if (BufferedMode) {
            auto SendContext = (ForwardedSend*)malloc(sizeof(ForwardedSend) + (size_t)Event->RECEIVE.TotalBufferLength);
            SendContext->TotalLength = Event->RECEIVE.TotalBufferLength;
            SendContext->Buffers[0].Buffer = (uint8_t*)SendContext + sizeof(ForwardedSend);
            SendContext->Buffers[0].Length = 0;
            for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                memcpy(
                    SendContext->Buffers[0].Buffer + SendContext->Buffers[0].Length,
                    Event->RECEIVE.Buffers[i].Buffer,
                    Event->RECEIVE.Buffers[i].Length);
                SendContext->Buffers[0].Length += Event->RECEIVE.Buffers[i].Length;
            }
            return SendContext;
        }
        auto SendContext = new(std::nothrow) ForwardedSend;
        SendContext->TotalLength = Event->RECEIVE.TotalBufferLength;
        for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
            SendContext->Buffers[i] = Event->RECEIVE.Buffers[i];
        }
        return SendContext;
    }
    static void Delete(ForwardedSend* SendContext) {
        if (BufferedMode) { free(SendContext); }
        else { delete SendContext; }
    }
};

QUIC_STATUS StreamCallback(
    _In_ struct MsQuicStream* /* Stream */,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    auto PeerStream = (MsQuicStream*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE: {
        //printf("s[%p] Received %llu bytes\n", Stream, Event->RECEIVE.TotalBufferLength);
        auto SendContext = ForwardedSend::New(Event);
        QUIC_SEND_FLAGS Flags = QUIC_SEND_FLAG_START;
        if (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN)   { Flags |= QUIC_SEND_FLAG_FIN; }
        if (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_0_RTT) { Flags |= QUIC_SEND_FLAG_ALLOW_0_RTT; }
        CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED(
            PeerStream->Send(SendContext->Buffers, Event->RECEIVE.BufferCount, Flags, SendContext)));
        return BufferedMode ? QUIC_STATUS_SUCCESS : QUIC_STATUS_PENDING;
    }
    case QUIC_STREAM_EVENT_SEND_COMPLETE: {
        auto SendContext = (ForwardedSend*)Event->SEND_COMPLETE.ClientContext;
        //printf("s[%p] Sent %llu bytes\n", Stream, SendContext->TotalLength);
        if (!BufferedMode && !Event->SEND_COMPLETE.Canceled && PeerStream) {
            PeerStream->ReceiveComplete(SendContext->TotalLength);
        }
        ForwardedSend::Delete(SendContext);
        break;
    }
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //printf("s[%p] Peer aborted send\n", Stream);
        if (PeerStream) PeerStream->Shutdown(Event->PEER_SEND_ABORTED.ErrorCode, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND);
        break;
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        //printf("s[%p] Peer aborted recv\n", Stream);
        if (PeerStream) PeerStream->Shutdown(Event->PEER_RECEIVE_ABORTED.ErrorCode, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //printf("s[%p] Shutdown complete\n", Stream);
        if (PeerStream) PeerStream->Context = nullptr;
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS ConnectionCallback(
    _In_ struct MsQuicConnection* /* Connection */,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    auto PeerConn = (MsQuicConnection*)Context;
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //printf("c[%p] Connected\n", Connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //printf("c[%p] Shutdown by transport 0x%0x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        PeerConn->Shutdown(0); // TODO - What error code do we use?
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //printf("c[%p] Shutdown by peer 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        PeerConn->Shutdown(Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        //printf("c[%p] Peer stream started\n", Connection);
        auto PeerStream = new(std::nothrow) MsQuicStream(*PeerConn, Event->PEER_STREAM_STARTED.Flags, CleanUpAutoDelete, StreamCallback);
        auto LocalStream = new(std::nothrow) MsQuicStream(Event->PEER_STREAM_STARTED.Stream, CleanUpAutoDelete, StreamCallback, PeerStream);
        PeerStream->Context = LocalStream;
        //printf("s[%p] Started -> [%p]\n", LocalStream, PeerStream);
        break;
    }
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //printf("c[%p] Shutdown complete\n", Connection);
        if (PeerConn) PeerConn->Context = nullptr;
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS ListenerCallback(
    _In_ struct MsQuicListener*,
    _In_opt_ void*,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        auto BackEndConn = new(std::nothrow) MsQuicConnection(*Registration, CleanUpAutoDelete, ConnectionCallback);
        auto FrontEndConn = new(std::nothrow) MsQuicConnection(Event->NEW_CONNECTION.Connection, CleanUpAutoDelete, ConnectionCallback, BackEndConn);
        BackEndConn->Context = FrontEndConn;
        //printf("c[%p] Created -> [%p]\n", FrontEndConn, BackEndConn);
        CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED(BackEndConn->Start(*BackEndConfiguration, BackEndTarget, BackEndPort)));
        CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED(FrontEndConn->SetConfiguration(*FrontEndConfiguration)));
    }
    return QUIC_STATUS_SUCCESS;
}

int QUIC_MAIN_EXPORT main(int argc, char **argv) {
    if (!ParseArgs(argc, argv)) {
        printf(USAGE);
        return 1;
    }

    MsQuicApi _MsQuic;
    CXPLAT_FRE_ASSERT(_MsQuic.IsValid());
    MsQuic = &_MsQuic;
    MsQuicRegistration Reg(true);
    Registration = &Reg;
    MsQuicSettings Settings;
    Settings.SetSendBufferingEnabled(false);
    Settings.SetPeerBidiStreamCount(1000);
    Settings.SetPeerUnidiStreamCount(1000);
    MsQuicConfiguration FrontEndConfig(Reg, Alpn, Settings, MsQuicCredentialConfig(QUIC_CREDENTIAL_FLAG_NONE, &Cert));
    CXPLAT_FRE_ASSERT(FrontEndConfig.IsValid());
    FrontEndConfiguration = &FrontEndConfig;
    MsQuicConfiguration BackEndConfig(Reg, Alpn, Settings, MsQuicCredentialConfig(QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION));
    CXPLAT_FRE_ASSERT(BackEndConfig.IsValid());
    BackEndConfiguration = &BackEndConfig;
    MsQuicListener Listener(Reg, CleanUpManual, ListenerCallback);
    CXPLAT_FRE_ASSERT(Listener.IsValid());
    CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED(Listener.Start(Alpn, QuicAddr(QUIC_ADDRESS_FAMILY_UNSPEC, FrontEndPort))));

    printf("Press Enter to exit.\n\n");
    getchar();
    return 0;
}
