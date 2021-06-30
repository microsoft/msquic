/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic Path Unittest

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "PathTest.cpp.clog.h"
#endif

struct PathTestContext {
    CxPlatEvent ShutdownEvent;
    MsQuicConnection* Connection {nullptr};
    bool PeerAddrChanged {false};

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        PathTestContext* Ctx = static_cast<PathTestContext*>(Context);
        Ctx->Connection = Conn;
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->Connection = nullptr;
            Ctx->ShutdownEvent.Set();
        }
        else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED) {
            Ctx->PeerAddrChanged = true;
        }
        return QUIC_STATUS_SUCCESS;
    }
};

void
QuicTestLocalPathChanges(
    _In_ int Family
    )
{
    MsQuicRegistration Registration;
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicAlpn Alpn("MsQuicTest");

    MsQuicConfiguration ServerConfiguration(Registration, Alpn, ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, Alpn, ClientCredConfig);
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    PathTestContext Context;
    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    TEST_QUIC_SUCCEEDED(Connection.StartLocalhost(ClientConfiguration, ServerLocalAddr));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));

    CxPlatSleep(1000);
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    QuicAddr OrigLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(OrigLocalAddr));
    QuicAddr NewLocalAddr(OrigLocalAddr);
    
    
    for (int i = 0; i < 50; i++) {
        NewLocalAddr.IncrementPort();
        ReplaceAddressHelper AddrHelper(OrigLocalAddr.SockAddr, NewLocalAddr.SockAddr);
        Connection.SetKeepAlive(25);

        bool ServerAddressUpdated = false;
        uint32_t Try = 0;
        do {
            if (Try != 0) {
                CxPlatSleep(200);
            }
            QuicAddr ServerRemoteAddr;
            TEST_QUIC_SUCCEEDED(Context.Connection->GetRemoteAddr(ServerRemoteAddr));
            if (Context.PeerAddrChanged &&
                QuicAddrCompare(&NewLocalAddr.SockAddr, &ServerRemoteAddr.SockAddr)) {
                ServerAddressUpdated = true;
                Context.PeerAddrChanged = false;
                break;
            }
        } while (++Try <= 3);
        TEST_TRUE(ServerAddressUpdated);
        Connection.SetKeepAlive(0);
    }

    CxPlatSleep(1000);
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    Connection.Shutdown(1);
    Context.Connection->Shutdown(1);

    Context.ShutdownEvent.WaitTimeout(2000);
}
