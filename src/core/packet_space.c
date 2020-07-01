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
    QUIC_STATUS Status;
    QUIC_PACKET_SPACE* Packets;

    Packets = QUIC_ALLOC_NONPAGED(sizeof(QUIC_PACKET_SPACE));
    if (Packets == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "packet space",
            sizeof(QUIC_PACKET_SPACE));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    QuicZeroMemory(Packets, sizeof(QUIC_PACKET_SPACE));
    Packets->Connection = Connection;
    Packets->EncryptLevel = EncryptLevel;

    Status = QuicAckTrackerInitialize(&Packets->AckTracker);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    *NewPackets = Packets;
    Packets = NULL;

Error:

    if (Packets != NULL) {
        QUIC_FREE(Packets);
    }

    return Status;
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
        QUIC_RECV_DATAGRAM* Datagram = Packets->DeferredDatagrams;
        do {
            Datagram->QueuedOnConnection = FALSE;
        } while ((Datagram = Datagram->Next) != NULL);
        QuicDataPathBindingReturnRecvDatagrams(Packets->DeferredDatagrams);
    }

    QuicAckTrackerUninitialize(&Packets->AckTracker);

    QUIC_FREE(Packets);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketSpaceReset(
    _In_ QUIC_PACKET_SPACE* Packets
    )
{
    QuicAckTrackerReset(&Packets->AckTracker);
}
