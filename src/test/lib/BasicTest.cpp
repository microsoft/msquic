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
void
ListenerDoNothingCallback(
    _In_ TestListener* /* Listener */,
    _In_ HQUIC /* ConnectionHandle */
    )
{
    TEST_FAILURE("This callback should never be called!");
}

void QuicTestCreateListener()
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        TestListener Listener(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener.IsValid());
    }
}

void QuicTestStartListener()
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        TestListener Listener(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start());
    }

    {
        TestListener Listener(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener.IsValid());
        QuicAddr LocalAddress(AF_UNSPEC);
        TEST_QUIC_SUCCEEDED(Listener.Start(&LocalAddress.SockAddr));
    }
}

void QuicTestStartListenerMultiAlpns()
{
    MsQuicSession Session("MsQuicTest1", "MsQuicTest2");
    TEST_TRUE(Session.IsValid());

    {
        TestListener Listener(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start());
    }

    {
        TestListener Listener(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener.IsValid());
        QuicAddr LocalAddress(AF_UNSPEC);
        TEST_QUIC_SUCCEEDED(Listener.Start(&LocalAddress.SockAddr));
    }
}

void QuicTestStartListenerImplicit(_In_ int Family)
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        TestListener Listener(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener.IsValid());

        QuicAddr LocalAddress(Family == 4 ? AF_INET : AF_INET6);
        TEST_QUIC_SUCCEEDED(Listener.Start(&LocalAddress.SockAddr));
    }
}

void QuicTestStartTwoListeners()
{
    MsQuicSession Session1;
    TEST_TRUE(Session1.IsValid());
    MsQuicSession Session2("MsQuicTest2");
    TEST_TRUE(Session2.IsValid());

    {
        TestListener Listener1(Session1.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener1.IsValid());
        TEST_QUIC_SUCCEEDED(Listener1.Start());

        QuicAddr LocalAddress;
        TEST_QUIC_SUCCEEDED(Listener1.GetLocalAddr(LocalAddress));

        TestListener Listener2(Session2.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener2.IsValid());
        TEST_QUIC_SUCCEEDED(Listener2.Start(&LocalAddress.SockAddr));
    }
}

void QuicTestStartTwoListenersSameALPN()
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());
    MsQuicSession Session2("MsQuicTest", "MsQuicTest2");
    TEST_TRUE(Session2.IsValid());

    {
        //
        // Both try to listen on the same, single ALPN
        //
        TestListener Listener1(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener1.IsValid());
        TEST_QUIC_SUCCEEDED(Listener1.Start());

        QuicAddr LocalAddress;
        TEST_QUIC_SUCCEEDED(Listener1.GetLocalAddr(LocalAddress));

        TestListener Listener2(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener2.IsValid());
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_STATE,
            Listener2.Start(&LocalAddress.SockAddr));
    }

    {
        //
        // First listener on two ALPNs and second overlaps one of those.
        //
        TestListener Listener1(Session2.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener1.IsValid());
        TEST_QUIC_SUCCEEDED(Listener1.Start());

        QuicAddr LocalAddress;
        TEST_QUIC_SUCCEEDED(Listener1.GetLocalAddr(LocalAddress));

        TestListener Listener2(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener2.IsValid());
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_STATE,
            Listener2.Start(&LocalAddress.SockAddr));
    }

    {
        //
        // First listener on one ALPN and second with two (one that overlaps).
        //
        TestListener Listener1(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener1.IsValid());
        TEST_QUIC_SUCCEEDED(Listener1.Start());

        QuicAddr LocalAddress;
        TEST_QUIC_SUCCEEDED(Listener1.GetLocalAddr(LocalAddress));

        TestListener Listener2(Session2.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener2.IsValid());
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_STATE,
            Listener2.Start(&LocalAddress.SockAddr));
    }
}

void QuicTestStartListenerExplicit(_In_ int Family)
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        TestListener Listener(Session.Handle, ListenerDoNothingCallback);
        TEST_TRUE(Listener.IsValid());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;
        QuicAddr LocalAddress(QuicAddr(QuicAddrFamily, true), TestUdpPortBase);
        QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
        while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
            LocalAddress.IncrementPort();
            Status = Listener.Start(&LocalAddress.SockAddr);
        }
        TEST_QUIC_SUCCEEDED(Status);
    }
}

void QuicTestCreateConnection()
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        TestConnection Connection(Session);
        TEST_TRUE(Connection.IsValid());
    }
}

void QuicTestBindConnectionImplicit(_In_ int Family)
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        TestConnection Connection(Session);
        TEST_TRUE(Connection.IsValid());

        QuicAddr LocalAddress(Family == 4 ? AF_INET : AF_INET6);
        TEST_QUIC_SUCCEEDED(Connection.SetLocalAddr(LocalAddress));
    }
}

void QuicTestBindConnectionExplicit(_In_ int Family)
{
    MsQuicSession Session;
    TEST_TRUE(Session.IsValid());

    {
        TestConnection Connection(Session);
        TEST_TRUE(Connection.IsValid());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;
        QuicAddr LocalAddress(QuicAddr(QuicAddrFamily, true), TestUdpPortBase);
        QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
        while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
            LocalAddress.IncrementPort();
            Status = Connection.SetLocalAddr(LocalAddress);
        }
        TEST_QUIC_SUCCEEDED(Status);
    }
}
