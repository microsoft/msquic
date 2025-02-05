/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Basic MsQuic API Functionality.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "BasicTest.cpp.clog.h"
#endif

_Function_class_(NEW_CONNECTION_CALLBACK)
static
bool
ListenerDoNothingCallback(
    _In_ TestListener* /* Listener */,
    _In_ HQUIC /* ConnectionHandle */
    )
{
    TEST_FAILURE("This callback should never be called!");
    return false;
}

void QuicTestCreateListener()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    {
        TestListener Listener(Registration, ListenerDoNothingCallback, nullptr);
        TEST_TRUE(Listener.IsValid());
    }

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerDoNothingCallback, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
    }
}

void QuicTestStartListener()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn("MsQuicTest");
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerDoNothingCallback, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, Alpn.Length()));
    }

    {
        TestListener Listener(Registration, ListenerDoNothingCallback, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        QuicAddr LocalAddress(QUIC_ADDRESS_FAMILY_UNSPEC);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, Alpn.Length(), &LocalAddress.SockAddr));
    }
}

void QuicTestStartListenerMultiAlpns()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn("MsQuicTest1", "MsQuicTest2");
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerDoNothingCallback, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, Alpn.Length()));
    }

    {
        TestListener Listener(Registration, ListenerDoNothingCallback, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        QuicAddr LocalAddress(QUIC_ADDRESS_FAMILY_UNSPEC);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, Alpn.Length(), &LocalAddress.SockAddr));
    }
}

void QuicTestStartListenerImplicit(_In_ int Family)
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn("MsQuicTest");
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerDoNothingCallback, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());

        QuicAddr LocalAddress(Family == 4 ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, Alpn.Length(), &LocalAddress.SockAddr));
    }
}

void QuicTestStartTwoListeners()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn1("MsQuicTest");
    MsQuicConfiguration ServerConfiguration1(Registration, Alpn1, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration1.IsValid());
    MsQuicAlpn Alpn2("MsQuicTest2");
    MsQuicConfiguration ServerConfiguration2(Registration, Alpn2, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration2.IsValid());

    {
        TestListener Listener1(Registration, ListenerDoNothingCallback, ServerConfiguration1);
        TEST_TRUE(Listener1.IsValid());
        TEST_QUIC_SUCCEEDED(Listener1.Start(Alpn1, Alpn1.Length()));

        QuicAddr LocalAddress;
        TEST_QUIC_SUCCEEDED(Listener1.GetLocalAddr(LocalAddress));

        TestListener Listener2(Registration, ListenerDoNothingCallback, ServerConfiguration2);
        TEST_TRUE(Listener2.IsValid());
        TEST_QUIC_SUCCEEDED(Listener2.Start(Alpn2, Alpn2.Length(), &LocalAddress.SockAddr));
    }
}

void QuicTestStartTwoListenersSameALPN()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn1("MsQuicTest");
    MsQuicConfiguration ServerConfiguration1(Registration, Alpn1, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration1.IsValid());
    MsQuicAlpn Alpn2("MsQuicTest", "MsQuicTest2");
    MsQuicConfiguration ServerConfiguration2(Registration, Alpn2, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration2.IsValid());

    {
        //
        // Both try to listen on the same, single ALPN
        //
        TestListener Listener1(Registration, ListenerDoNothingCallback, ServerConfiguration1);
        TEST_TRUE(Listener1.IsValid());
        TEST_QUIC_SUCCEEDED(Listener1.Start(Alpn1, Alpn1.Length()));

        QuicAddr LocalAddress;
        TEST_QUIC_SUCCEEDED(Listener1.GetLocalAddr(LocalAddress));

        TestListener Listener2(Registration, ListenerDoNothingCallback, ServerConfiguration1);
        TEST_TRUE(Listener2.IsValid());
        TEST_QUIC_STATUS(
            QUIC_STATUS_ALPN_IN_USE,
            Listener2.Start(Alpn1, Alpn1.Length(), &LocalAddress.SockAddr));
    }

    {
        //
        // First listener on two ALPNs and second overlaps one of those.
        //
        TestListener Listener1(Registration, ListenerDoNothingCallback, ServerConfiguration2);
        TEST_TRUE(Listener1.IsValid());
        TEST_QUIC_SUCCEEDED(Listener1.Start(Alpn2, Alpn2.Length()));

        QuicAddr LocalAddress;
        TEST_QUIC_SUCCEEDED(Listener1.GetLocalAddr(LocalAddress));

        TestListener Listener2(Registration, ListenerDoNothingCallback, ServerConfiguration1);
        TEST_TRUE(Listener2.IsValid());
        TEST_QUIC_STATUS(
            QUIC_STATUS_ALPN_IN_USE,
            Listener2.Start(Alpn1, Alpn1.Length(), &LocalAddress.SockAddr));
    }

    {
        //
        // First listener on one ALPN and second with two (one that overlaps).
        //
        TestListener Listener1(Registration, ListenerDoNothingCallback, ServerConfiguration1);
        TEST_TRUE(Listener1.IsValid());
        TEST_QUIC_SUCCEEDED(Listener1.Start(Alpn1, Alpn1.Length()));

        QuicAddr LocalAddress;
        TEST_QUIC_SUCCEEDED(Listener1.GetLocalAddr(LocalAddress));

        TestListener Listener2(Registration, ListenerDoNothingCallback, ServerConfiguration2);
        TEST_TRUE(Listener2.IsValid());
        TEST_QUIC_STATUS(
            QUIC_STATUS_ALPN_IN_USE,
            Listener2.Start(Alpn2, Alpn2.Length(), &LocalAddress.SockAddr));
    }
}

void QuicTestStartListenerExplicit(_In_ int Family)
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn("MsQuicTest");
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerDoNothingCallback, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
        QuicAddr LocalAddress(QuicAddr(QuicAddrFamily, true), TestUdpPortBase);
        if (UseDuoNic) {
            QuicAddrSetToDuoNic(&LocalAddress.SockAddr);
        }
        QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
        while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
            LocalAddress.IncrementPort();
            Status = Listener.Start(Alpn, Alpn.Length(), &LocalAddress.SockAddr);
        }
        TEST_QUIC_SUCCEEDED(Status);
    }
}

void QuicTestCreateConnection()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    {
        TestConnection Connection(Registration);
        TEST_TRUE(Connection.IsValid());
    }
}

void QuicTestBindConnectionImplicit(_In_ int Family)
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    {
        TestConnection Connection(Registration);
        TEST_TRUE(Connection.IsValid());

        QuicAddr LocalAddress(Family == 4 ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6);
        TEST_QUIC_SUCCEEDED(Connection.SetLocalAddr(LocalAddress));
    }
}

void QuicTestBindConnectionExplicit(_In_ int Family)
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    {
        TestConnection Connection(Registration);
        TEST_TRUE(Connection.IsValid());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
        QuicAddr LocalAddress(QuicAddr(QuicAddrFamily, true), TestUdpPortBase);
        if (UseDuoNic) {
            QuicAddrSetToDuoNic(&LocalAddress.SockAddr);
        }
        QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
        while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
            LocalAddress.IncrementPort();
            Status = Connection.SetLocalAddr(LocalAddress);
        }
        TEST_QUIC_SUCCEEDED(Status);
    }
}

void QuicTestAddrFunctions(_In_ int Family)
{
    QUIC_ADDR SockAddr;
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;

    // initialize the struct to 0xFF to ensure any code issues are caught by the following tests
    memset(&SockAddr, 0xFF, sizeof(SockAddr));

    QuicAddrSetFamily(&SockAddr, QuicAddrFamily);
    TEST_TRUE(QuicAddrGetFamily(&SockAddr) == QuicAddrFamily);

    QuicAddrSetToLoopback(&SockAddr);

    if (QuicAddrFamily == QUIC_ADDRESS_FAMILY_INET) {
        TEST_TRUE((SockAddr.Ipv4.sin_addr.s_addr & 0x00FFFF00UL) == 0);
    } else {
        for (unsigned long i = 0; i < sizeof(SockAddr.Ipv6.sin6_addr) - 1; i++) {
            TEST_TRUE(SockAddr.Ipv6.sin6_addr.s6_addr[i] == 0);
        }
    }

    TEST_TRUE(QuicAddrGetFamily(&SockAddr) == QuicAddrFamily);
}
