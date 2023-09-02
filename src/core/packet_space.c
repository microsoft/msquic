/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    All the information related to receiving packets in a packet number space at
    a given encryption level.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "packet_space.c.clog.h"
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPacketSpaceInitialize(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_ENCRYPT_LEVEL EncryptLevel,
    _Out_ QUIC_PACKET_SPACE** NewPackets
    )
{
    QUIC_PACKET_SPACE* Packets = CxPlatPoolAlloc(&QuicLibraryGetPerProc()->PacketSpacePool);
    if (Packets == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "packet space",
            sizeof(QUIC_PACKET_SPACE));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    CxPlatZeroMemory(Packets, sizeof(QUIC_PACKET_SPACE));
    Packets->Connection = Connection;
    Packets->EncryptLevel = EncryptLevel;
    QuicAckTrackerInitialize(&Packets->AckTracker);

    *NewPackets = Packets;

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPacketSpaceUninitialize(
    _In_ QUIC_PACKET_SPACE* Packets
    )
{
    //
    // Release any pending packets back to the binding.
    //
    if (Packets->DeferredPackets != NULL) {
        QUIC_RX_PACKET* Packet = Packets->DeferredPackets;
        do {
            Packet->QueuedOnConnection = FALSE;
        } while ((Packet = (QUIC_RX_PACKET*)Packet->Next) != NULL);
        CxPlatRecvDataReturn((CXPLAT_RECV_DATA*)Packets->DeferredPackets);
    }

    QuicAckTrackerUninitialize(&Packets->AckTracker);
    CxPlatPoolFree(&QuicLibraryGetPerProc()->PacketSpacePool, Packets);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketSpaceReset(
    _In_ QUIC_PACKET_SPACE* Packets
    )
{
    QuicAckTrackerReset(&Packets->AckTracker);
}
