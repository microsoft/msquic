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
    uint32_t CurProcIndex = CxPlatProcCurrentNumber();
    QUIC_PACKET_SPACE* Packets = CxPlatPoolAlloc(&MsQuicLib.PerProc[CurProcIndex].PacketSpacePool);
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
    if (Packets->DeferredDatagrams != NULL) {
        CXPLAT_RECV_DATA* Datagram = Packets->DeferredDatagrams;
        do {
            Datagram->QueuedOnConnection = FALSE;
        } while ((Datagram = Datagram->Next) != NULL);
        CxPlatRecvDataReturn(Packets->DeferredDatagrams);
    }

    QuicAckTrackerUninitialize(&Packets->AckTracker);

    uint32_t CurProcIndex = CxPlatProcCurrentNumber();
    CxPlatPoolFree(&MsQuicLib.PerProc[CurProcIndex].PacketSpacePool, Packets);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketSpaceReset(
    _In_ QUIC_PACKET_SPACE* Packets
    )
{
    QuicAckTrackerReset(&Packets->AckTracker);
}
