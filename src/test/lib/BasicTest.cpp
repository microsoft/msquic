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

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES

namespace {

struct RegistrationCloseContext {
    CxPlatEvent Event;
};

_Function_class_(QUIC_REGISTRATION_CLOSE_CALLBACK)
void
QUIC_API RegistrationCloseCallback(
    _In_opt_ void* Context
    )
{
    RegistrationCloseContext* CloseContext = (RegistrationCloseContext*)Context;
    CloseContext->Event.Set();
}

}

#endif

void QuicTestRegistrationOpenClose()
{
    //
    // Open and syncrhonous close
    //
    {
        MsQuicRegistration Registration;
        TEST_TRUE(Registration.IsValid());
    }

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    //
    // Open and asyncrhonous close
    //
    {
        MsQuicRegistration Registration;
        TEST_TRUE(Registration.IsValid());

        RegistrationCloseContext Context{};
        Registration.CloseAsync(RegistrationCloseCallback, &Context);
        Context.Event.WaitForever();
    }
#endif
}

_Function_class_(NEW_CONNECTION_CALLBACK)
static
bool
QUIC_API
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

void QuicTestStartListenerImplicit(const FamilyArgs& Params)
{
    const int Family = Params.Family;
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

void QuicTestStartListenerExplicit(const FamilyArgs& Params)
{
    const int Family = Params.Family;
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

#if defined(__linux__)
static
void
QuicTestProbeReusePort(
    _In_ const QUIC_ADDR* Address,
    _Out_ int* Error
    )
{
    *Error = -1;
    const int AddressFamily =
        QuicAddrGetFamily(Address) == QUIC_ADDRESS_FAMILY_INET ? AF_INET : AF_INET6;
    int ProbeSocket = socket(AddressFamily, SOCK_DGRAM, IPPROTO_UDP);
    TEST_NOT_EQUAL(INVALID_SOCKET, ProbeSocket);

    int ReusePort = TRUE;
    int Result =
        setsockopt(
            ProbeSocket,
            SOL_SOCKET,
            SO_REUSEPORT,
            &ReusePort,
            sizeof(ReusePort));
    if (Result != 0) {
        close(ProbeSocket);
        TEST_EQUAL(0, Result);
        return;
    }
    Result =
        bind(
            ProbeSocket,
            &Address->Ip,
            AddressFamily == AF_INET ? sizeof(Address->Ipv4) : sizeof(Address->Ipv6));
    *Error = Result == 0 ? 0 : errno;
    close(ProbeSocket);
}

static
QUIC_STATUS
QUIC_API
QuicTestPartitionedListenerCallback(
    _In_ MsQuicListener*,
    _In_opt_ void*,
    _Inout_ QUIC_LISTENER_EVENT*
    )
{
    return QUIC_STATUS_SUCCESS;
}

void
QuicTestPartitionedListenerPort(const FamilyArgs& Params)
{
    const QUIC_ADDRESS_FAMILY Family =
        Params.Family == 4 ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    const uint16_t PartitionIndex = 1;
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn("MsQuicTest");

    {
        MsQuicListener Listener(
            Registration,
            CleanUpManual,
            QuicTestPartitionedListenerCallback);
        TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
        QUIC_STATUS SetStatus = Listener.SetPartitionId(PartitionIndex);
        if (SetStatus == QUIC_STATUS_INVALID_PARAMETER) {
            return;
        }
        TEST_QUIC_SUCCEEDED(SetStatus);
        QuicAddr DynamicAddress(Family);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &DynamicAddress.SockAddr));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(DynamicAddress));
        int ProbeError;
        QuicTestProbeReusePort(&DynamicAddress.SockAddr, &ProbeError);
        TEST_EQUAL(EADDRINUSE, ProbeError);
    }

    {
        MsQuicListener Listener(
            Registration,
            CleanUpManual,
            QuicTestPartitionedListenerCallback);
        TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Listener.SetPartitionId(PartitionIndex));
        QuicAddr ExplicitPortAddress(QuicAddr(Family), TestUdpPortBase);
        QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
        while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
            ExplicitPortAddress.IncrementPort();
            Status = Listener.Start(Alpn, &ExplicitPortAddress.SockAddr);
        }
        TEST_QUIC_SUCCEEDED(Status);
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ExplicitPortAddress));
        int ProbeError;
        QuicTestProbeReusePort(&ExplicitPortAddress.SockAddr, &ProbeError);
        TEST_EQUAL(0, ProbeError);
    }

    {
        MsQuicListener Listener(
            Registration,
            CleanUpManual,
            QuicTestPartitionedListenerCallback);
        TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
        QuicAddr DynamicAddress(Family);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, &DynamicAddress.SockAddr));
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(DynamicAddress));
        int ProbeError;
        QuicTestProbeReusePort(&DynamicAddress.SockAddr, &ProbeError);
        TEST_EQUAL(0, ProbeError);
    }
}
#endif

void QuicTestCreateConnection()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    {
        TestConnection Connection(Registration);
        TEST_TRUE(Connection.IsValid());
    }
}

void QuicTestBindConnectionImplicit(const FamilyArgs& Params)
{
    const int Family = Params.Family;
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    {
        TestConnection Connection(Registration);
        TEST_TRUE(Connection.IsValid());

        QuicAddr LocalAddress(Family == 4 ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6);
        TEST_QUIC_SUCCEEDED(Connection.SetLocalAddr(LocalAddress));
    }
}

void QuicTestBindConnectionExplicit(const FamilyArgs& Params)
{
    const int Family = Params.Family;
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

void QuicTestAddrFunctions(const FamilyArgs& Params)
{
    const int Family = Params.Family;
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
