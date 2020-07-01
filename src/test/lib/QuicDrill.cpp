/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic Packet-level tests.

Future:
    Additional test cases to implement:
        * Test packet number encoded larger than necessary with valid Initial
          packet.
        * Test reserved header flags, and packet number size mismatch.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "QuicDrill.cpp.clog.h"
#endif

extern "C" {
#include <quic_datapath.h>
}

void
QuicDrillTestVarIntEncoder(
    )
{
    auto output = QuicDrillEncodeQuicVarInt(0);
    TEST_EQUAL(output[0], 0);

    output = QuicDrillEncodeQuicVarInt(0x3f);
    TEST_EQUAL(output[0], 0x3f);

    output = QuicDrillEncodeQuicVarInt(0x40);
    TEST_EQUAL(output[0], 0x40);
    TEST_EQUAL(output[1], 0x40);

    output = QuicDrillEncodeQuicVarInt(0x3fff);
    TEST_EQUAL(output[0], 0x7f);
    TEST_EQUAL(output[1], 0xff);

    output = QuicDrillEncodeQuicVarInt(0x4000);
    TEST_EQUAL(output[0], 0x80);
    TEST_EQUAL(output[1], 0x00);
    TEST_EQUAL(output[2], 0x40);

    output = QuicDrillEncodeQuicVarInt(0x3FFFFFFFUL);
    TEST_EQUAL(output[0], 0xbf);
    TEST_EQUAL(output[1], 0xff);
    TEST_EQUAL(output[2], 0xff);
    TEST_EQUAL(output[3], 0xff);

    output = QuicDrillEncodeQuicVarInt(0x40000000UL);
    TEST_EQUAL(output[0], 0xc0);
    TEST_EQUAL(output[1], 0x00);
    TEST_EQUAL(output[2], 0x00);
    TEST_EQUAL(output[3], 0x00);
    TEST_EQUAL(output[4], 0x40);

    output = QuicDrillEncodeQuicVarInt(0x3FFFFFFFFFFFFFFFULL);
    TEST_EQUAL(output[0], 0xff);
    TEST_EQUAL(output[1], 0xff);
    TEST_EQUAL(output[2], 0xff);
    TEST_EQUAL(output[3], 0xff);
    TEST_EQUAL(output[4], 0xff);
    TEST_EQUAL(output[5], 0xff);
    TEST_EQUAL(output[6], 0xff);
    TEST_EQUAL(output[7], 0xff);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(NEW_CONNECTION_CALLBACK)
static
void
QuicDrillConnectionCallbackHandler(
    _In_ TestListener* /* Listener */,
    _In_ HQUIC ConnectionHandle
    )
{
    TEST_FAILURE("Quic Drill listener received an unexpected event!");
    MsQuic->ConnectionClose(ConnectionHandle);
}

struct DrillSender {
    QUIC_DATAPATH* Datapath;
    QUIC_DATAPATH_BINDING* Binding;
    QUIC_ADDR ServerAddress;

    _IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_DATAPATH_RECEIVE_CALLBACK)
    static void
    DrillUdpRecvCallback(
        _In_ QUIC_DATAPATH_BINDING* /* Binding */,
        _In_ void* /* Context */,
        _In_ QUIC_RECV_DATAGRAM* RecvBufferChain
        )
    {
        QuicDataPathBindingReturnRecvDatagrams(RecvBufferChain);
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_DATAPATH_UNREACHABLE_CALLBACK)
    static void
    DrillUdpUnreachCallback(
        _In_ QUIC_DATAPATH_BINDING* /* Binding */,
        _In_ void* /* Context */,
        _In_ const QUIC_ADDR* /* RemoteAddress */
        )
    {
    }

    DrillSender() : Datapath(nullptr), Binding(nullptr) {}

    ~DrillSender() {
        if (Binding != nullptr) {
            QuicDataPathBindingDelete(Binding);
        }

        if (Datapath != nullptr) {
            QuicDataPathUninitialize(Datapath);
        }
    }

    QUIC_STATUS
    Initialize(
        _In_ const char* HostName,
        _In_ QUIC_ADDRESS_FAMILY Family,
        _In_ uint16_t NetworkPort
        )
    {
        QUIC_STATUS Status =
            QuicDataPathInitialize(
                0,
                DrillUdpRecvCallback,
                DrillUdpUnreachCallback,
                &Datapath);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("Datapath init failed 0x%x", Status);
            return Status;
        }

        QuicAddrSetFamily(&ServerAddress, Family);

        Status =
            QuicDataPathResolveAddress(
                Datapath,
                HostName,
                &ServerAddress);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("Address resolution failed 0x%x", Status);
            return Status;
        }

        if (Family == AF_INET) {
            ServerAddress.Ipv4.sin_port = NetworkPort;
        } else {
            ServerAddress.Ipv6.sin6_port = NetworkPort;
        }

        Status =
            QuicDataPathBindingCreate(
                Datapath,
                nullptr,
                &ServerAddress,
                this,
                &Binding);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("Binding failed: 0x%x", Status);
        }
        return Status;
    }

    QUIC_STATUS
    Send(
        _In_ const DrillBuffer* PacketBuffer
        )
    {
        QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
        QUIC_FRE_ASSERT(PacketBuffer->size() <= UINT16_MAX);
        const uint16_t DatagramLength = (uint16_t) PacketBuffer->size();

        QUIC_DATAPATH_SEND_CONTEXT* SendContext =
            QuicDataPathBindingAllocSendContext(Binding, DatagramLength);

        QUIC_BUFFER* SendBuffer =
            QuicDataPathBindingAllocSendDatagram(SendContext, DatagramLength);

        if (SendBuffer == nullptr) {
            TEST_FAILURE("Buffer null");
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            return Status;
        }

        // Copy test packet into SendBuffer.
        memcpy(SendBuffer->Buffer, PacketBuffer->data(), DatagramLength);

        Status =
            QuicDataPathBindingSendTo(
                Binding,
                &ServerAddress,
                SendContext);

        return Status;
    }


};

bool
QuicDrillInitialPacketFailureTest(
    _In_ QUIC_ADDRESS_FAMILY QuicAddrFamily,
    _In_ const DrillInitialPacketDescriptor& InitialPacketDescriptor
    )
{
    QUIC_STATUS Status;
    QUIC_LISTENER_STATISTICS Stats;
    uint64_t DroppedPacketsBefore;
    uint64_t DroppedPacketsAfter;

    QuicAddr ServerAddress(QuicAddrFamily);
    DrillSender Sender;
    const uint8_t Disabled = FALSE;
    const uint8_t Enabled = TRUE;

    Status =
        MsQuic->SetParam(
            nullptr,
            QUIC_PARAM_LEVEL_GLOBAL,
            QUIC_PARAM_GLOBAL_ENCRYPTION,
            sizeof(Disabled),
            &Disabled);
    if (QUIC_FAILED(Status)) {
        TEST_FAILURE("Failed to disable encryption for test. 0x%x", Status);
        return false;
    }

    MsQuicSession Session;
    if (!Session.IsValid()) {
        TEST_FAILURE("Session not valid!");
        goto Failure;
    }

    {
        //
        // Start the server.
        //
        TestListener Listener(Session.Handle, QuicDrillConnectionCallbackHandler);

        Status = Listener.Start(&ServerAddress.SockAddr);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("ListenerStart failed, 0x%x.", Status);
            goto Failure;
        }

        //
        // Get server address (port) here.
        //
        Status = Listener.GetLocalAddr(ServerAddress);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->GetParam failed, 0x%x.", Status);
            goto Failure;
        }

        Status =
            Sender.Initialize(
                QUIC_LOCALHOST_FOR_AF(QuicAddrFamily),
                QuicAddrFamily,
                (QuicAddrFamily == AF_INET) ?
                    ServerAddress.SockAddr.Ipv4.sin_port :
                    ServerAddress.SockAddr.Ipv6.sin6_port);
        if (QUIC_FAILED(Status)) {
            goto Failure;
        }

        DrillBuffer PacketBuffer = InitialPacketDescriptor.write();

        Status = Listener.GetStatistics(Stats);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("Get Listener statistics before test failed, 0x%x.", Status);
            goto Failure;
        }
        DroppedPacketsBefore = Stats.Binding.Recv.DroppedPackets;

        //
        // Send test packet to the server.
        //
        Status = Sender.Send(&PacketBuffer);
        if (QUIC_FAILED(Status)) {
            goto Failure;
        }

        //
        // Generously wait for server to process packet.
        //
        QuicSleep(100);

        Status = Listener.GetStatistics(Stats);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("Get Listener statistics after test failed, 0x%x.", Status);
            goto Failure;
        }
        DroppedPacketsAfter = Stats.Binding.Recv.DroppedPackets;

        //
        // Validate the server rejected the packet just sent.
        // N.B. Could fail if the server has other packets sent to it accidentally.
        //
        if (DroppedPacketsAfter - DroppedPacketsBefore != 1) {
            TEST_FAILURE(
                "DroppedPacketsAfter - DroppedPacketsBefore (%d) not equal to 1",
                DroppedPacketsAfter - DroppedPacketsBefore);
            goto Failure;
        }
    }
    return true;

Failure:
    Status =
        MsQuic->SetParam(
            nullptr,
            QUIC_PARAM_LEVEL_GLOBAL,
            QUIC_PARAM_GLOBAL_ENCRYPTION,
            sizeof(Enabled),
            &Enabled);
    if (QUIC_FAILED(Status)) {
        TEST_FAILURE("Failed to re-enable encryption after test. 0x%x", Status);
    }
    return false;
}

#define VALID_CID_LENGTH_SHORT 8
#define VALID_CID_LENGTH_LONG 20
#define INVALID_CID_LENGTH_SHORT 7
#define INVALID_CID_LENGTH_LONG 21

void
QuicDrillTestInitialCid(
    _In_ int Family,
    _In_ bool Source, // or Dest
    _In_ bool ValidActualLength, // or invalid
    _In_ bool Short, // or long
    _In_ bool ValidLengthField // or invalid
    )
{
/**
 * SourceCid valid length, but longer than valid length field indicates.
 * SourceCid valid length, but shorter than valid length field indicates.
 * SourceCid valid length, but shorter than invalid length field.
 * SourceCid valid length, but longer than invalid length field.
 * SourceCid invalidly short, but length field indicates valid length.
 * SourceCid invalidly long, but length field indicates valid length.
 * SourceCid invalidly short, and length field matches.
 * SourceCid invalidly long, and length field matches.
 * (Ditto for DestCid)

   (source, dest), [(valid length, invalid length), (valid length field, invalid length field)], (short, long)

*/

    uint8_t ActualCidLength;
    uint8_t CidLengthField;

    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;
    DrillInitialPacketDescriptor InitialDescriptor;

    // Calculate the test parameters
    if (ValidActualLength) {
        if (Short) {
            ActualCidLength = VALID_CID_LENGTH_SHORT;
        } else {
            ActualCidLength = VALID_CID_LENGTH_LONG;
        }

        if (ValidLengthField) {
            // When both lengths are valid, we want to make the field different
            // than the actual length so they don't agree.
            if (!Short) {
                CidLengthField = VALID_CID_LENGTH_SHORT;
            } else {
                CidLengthField = VALID_CID_LENGTH_LONG;
            }
        } else {
            // When the length field is invalid, but the actual length valid,
            // we want to make the length field very invalid.
            if (!Short) {
                CidLengthField = INVALID_CID_LENGTH_SHORT;
            } else {
                CidLengthField = INVALID_CID_LENGTH_LONG;
            }
        }
    } else {
        if (Short) {
            ActualCidLength = INVALID_CID_LENGTH_SHORT;
        } else {
            ActualCidLength = INVALID_CID_LENGTH_LONG;
        }

        if (ValidLengthField) {
            // When the actual length is invalid, but the length field valid,
            // make the field the closest valid value.
            if (Short) {
                CidLengthField = VALID_CID_LENGTH_SHORT;
            } else {
                CidLengthField = VALID_CID_LENGTH_LONG;
            }
        } else {
            // When both length field and actual length are invalid, make the
            // values agree.
            if (Short) {
                CidLengthField = INVALID_CID_LENGTH_SHORT;
            } else {
                CidLengthField = INVALID_CID_LENGTH_LONG;
            }
        }
    }

    DrillBuffer TestCid;
    for (int value = 0; value < ActualCidLength; value++) {
        TestCid.push_back(0xff - (uint8_t) value); // Make this Cid look different from the default one.
    }

    if (Source) {
        InitialDescriptor.SourceCid.clear();
        InitialDescriptor.SourceCid.insert(InitialDescriptor.SourceCid.begin(), TestCid.begin(), TestCid.end());
        InitialDescriptor.SourceCidLen = &CidLengthField;
    } else {
        InitialDescriptor.DestCid.clear();
        InitialDescriptor.DestCid.insert(InitialDescriptor.DestCid.begin(), TestCid.begin(), TestCid.end());
        InitialDescriptor.DestCidLen = &CidLengthField;
    }

    QuicDrillInitialPacketFailureTest(QuicAddrFamily, InitialDescriptor);
}

void
QuicDrillTestInitialToken(
    _In_ int Family
    )
{
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? AF_INET : AF_INET6;
    const uint8_t GeneratedTokenLength = 20;
    uint64_t TokenLen;

    // Token length is larger than actual token.
    {
        DrillInitialPacketDescriptor InitialDescriptor;

        for (uint8_t TokenValue = 0; TokenValue < GeneratedTokenLength; TokenValue++) {
            InitialDescriptor.Token.push_back(TokenValue);
        }
        TokenLen = GeneratedTokenLength + 1;
        InitialDescriptor.TokenLen = &TokenLen;

        if (!QuicDrillInitialPacketFailureTest(QuicAddrFamily, InitialDescriptor)) {
            return;
        }
    }

    // Token length is shorter than actual token.
    {
        DrillInitialPacketDescriptor InitialDescriptor;

        for (uint8_t TokenValue = 0; TokenValue < GeneratedTokenLength; TokenValue++) {
            InitialDescriptor.Token.push_back(TokenValue);
        }
        TokenLen = GeneratedTokenLength - 1;
        InitialDescriptor.TokenLen = &TokenLen;

        if (!QuicDrillInitialPacketFailureTest(QuicAddrFamily, InitialDescriptor)) {
            return;
        }
    }

    // Token length is non-zero and token is not present.
    {
        DrillInitialPacketDescriptor InitialDescriptor;

        TokenLen = 1;
        InitialDescriptor.TokenLen = &TokenLen;

        if (!QuicDrillInitialPacketFailureTest(QuicAddrFamily, InitialDescriptor)) {
            return;
        }
    }
}
