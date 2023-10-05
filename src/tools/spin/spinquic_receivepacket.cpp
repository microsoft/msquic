/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include <time.h>
#include <stdio.h>

#include <vector>
#include <map>
#include <mutex>
#include <algorithm>


#define QUIC_TEST_APIS 1 // Needed for self signed cert API
#define QUIC_API_ENABLE_INSECURE_FEATURES 1 // Needed for disabling 1-RTT encryption
#define QUIC_API_ENABLE_PREVIEW_FEATURES // Needed for VN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "msquichelper.h"
#include "precomp.h"
#include "msquic.h"

#define ASSERT_ON_FAILURE(x) \
    do { \
        QUIC_STATUS _STATUS; \
        CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED((_STATUS = x))); \
    } while (0)
#define ASSERT_ON_NOT(x) CXPLAT_FRE_ASSERT(x)

static QUIC_API_TABLE MsQuic;


struct ListenerContext {
    HQUIC ServerConfiguration;
    HQUIC *Connection;
    uint16_t ThreadID;
};

const uint32_t MaxBufferSizes[] = { 0, 1, 2, 32, 50, 256, 500, 1000, 1024, 1400, 5000, 10000, 64000, 10000000 };
static const size_t BufferCount = ARRAYSIZE(MaxBufferSizes);


class PacketWriter
{
    uint32_t QuicVersion;
    uint8_t CryptoBuffer[4096];
    uint16_t CryptoBufferLength;

    static
    void
    WriteInitialCryptoFrame(
        _In_z_ const char* Alpn,
        _In_z_ const char* Sni,
        _Inout_ uint16_t* Offset,
        _In_ uint16_t BufferLength,
        _Out_writes_to_(BufferLength, *Offset)
            uint8_t* Buffer
        )
{

}

public:

    PacketWriter(
        _In_ uint32_t Version,
        _In_z_ const char* Alpn,
        _In_z_ const char* Sni
        )
{

}

    void
    WriteClientInitialPacket(
        _In_ uint32_t PacketNumber,
        _In_ uint8_t CidLength,
        _In_ uint16_t BufferLength,
        _Out_writes_to_(BufferLength, *PacketLength)
            uint8_t* Buffer,
        _Out_ uint16_t* PacketLength,
        _Out_ uint16_t* HeaderLength
        )
{

}
};


QUIC_STATUS
QUIC_API
ServerStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Context);
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        free(Event->SEND_COMPLETE.ClientContext);
        printf("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream.
        //
        printf("[strm][%p] Data received\n", Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer shut down\n", Stream);
        MsQuic.StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", Stream);
        MsQuic.StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        printf("[strm][%p] All done\n", Stream);
        MsQuic.StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QUIC_API
ServerConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Context);
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        printf("[conn][%p] Connected\n", Connection);
        MsQuic.ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            printf("[conn][%p] Successfully shut down on idle.\n", Connection);
        } else {
            printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        printf("[conn][%p] All done\n", Connection);
        MsQuic.ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        //
        // The peer has started/created a new stream. The app MUST set the
        // callback handler before returning.
        //
        printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
        MsQuic.SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerStreamCallback, NULL);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        //
        // The connection succeeded in doing a TLS resumption of a previous
        // connection's session.
        //
        printf("[conn][%p] Connection resumed!\n", Connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}


QUIC_STATUS
QUIC_API
ServerListenerCallback(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Listener);
    UNREFERENCED_PARAMETER(Context);
    HQUIC ServerConfiguration = ((ListenerContext*)Context)->ServerConfiguration;
    HQUIC Connection = *((ListenerContext*)Context)->Connection;
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        //
        // A new connection is being attempted by a client. For the handshake to
        // proceed, the server must provide a configuration for QUIC to use. The
        // app MUST set the callback handler before returning.
        //
        MsQuic.SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, NULL);
        Status = MsQuic.ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, ServerConfiguration);
        Connection = Event->NEW_CONNECTION.Connection;
        break;
    default:
        break;
    }
    return Status;
}



void makeServer(HQUIC *Listener){
    HQUIC Registration;
    QUIC_REGISTRATION_CONFIG RegConfig;
    RegConfig.AppName = "spinquic";
    RegConfig.ExecutionProfile = QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER;

    MsQuic.RegistrationOpen(&RegConfig, &Registration);
    HQUIC Connection;
    ListenerContext ListenerCtx = { nullptr, &Connection, 0};
    QUIC_ADDR sockAddr = { 0 };
    QUIC_SETTINGS QuicSettings{0};
    const uint64_t IdleTimeoutMs = 2000;
    QuicSettings.IdleTimeoutMs = IdleTimeoutMs;
    QuicSettings.IsSet.IdleTimeoutMs = TRUE;
    QuicSettings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    QuicSettings.IsSet.ServerResumptionLevel = TRUE;
    QuicSettings.PeerBidiStreamCount = 1;
    QuicSettings.IsSet.PeerBidiStreamCount = TRUE;
    auto CredConfig = CxPlatGetSelfSignedCert(CXPLAT_SELF_SIGN_CERT_USER, FALSE, NULL);

    QUIC_BUFFER Alpn = { sizeof("spin") - 1, (uint8_t*)"spin" };
    MsQuic.ConfigurationOpen(
                Registration, 
                &Alpn,
                Alpn.Length,
                &QuicSettings,
                sizeof(QuicSettings),
                nullptr,
                &ListenerCtx.ServerConfiguration);
     MsQuic.ConfigurationLoadCredential(
                ListenerCtx.ServerConfiguration,
                CredConfig);
   
    if (!QUIC_SUCCEEDED(
        (MsQuic.ListenerOpen(Registration, ServerListenerCallback, &ListenerCtx, Listener)))) {
        MsQuic.ListenerClose(*Listener);
    }

    QuicAddrSetFamily(&sockAddr, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&sockAddr, 9999);

    if (!QUIC_SUCCEEDED(MsQuic.ListenerStart(*Listener, &Alpn, 1, &sockAddr))) {
        MsQuic.ListenerClose(*Listener);
    }   
}

void start(){
    // make a server

    HQUIC Listener;
    makeServer(&Listener);
    
    // make a random parameter generator using fuzzing data
    // make a initial packet
    
    // PacketWriter* Writer;
    // uint64_t PacketNumber = 0;
    // uint8_t Packet[512] = {0};
    // uint16_t PacketLength, HeaderLength;
    // Writer->WriteClientInitialPacket(
    //     PacketNumber,
    //     sizeof(uint64_t),
    //     sizeof(Packet),
    //     Packet,
    //     &PacketLength,
    //     &HeaderLength);

    // send the packet


}

#ifdef FUZZING

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzData = new FuzzingData(data, size);
    if (!FuzzData->Initialize()) {
        return 0;
    }


    start();
    delete FuzzData;
    return 0;
}
#else
int
QUIC_MAIN_EXPORT
main()
{
   
    start();

    return 0;
}

#endif // FUZZING
