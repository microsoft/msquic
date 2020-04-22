/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Manages the unreliable datagram feature's functionality for a connection.

--*/

#include "precomp.h"

#ifdef QUIC_LOGS_WPP
#include "datagram.tmh"
#endif

#define DATAGRAM_FRAME_HEADER_LENGTH 3

#define QUIC_DATAGRAM_OVERHEAD(CidLength) \
(\
    MIN_SHORT_HEADER_LENGTH_V1 + \
    CidLength + \
    DATAGRAM_FRAME_HEADER_LENGTH \
)

uint16_t
QuicCalculateDatagramLength(
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_ uint16_t Mtu,
    _In_ uint8_t CidLength
    )
{
    return
        MaxUdpPayloadSizeForFamily(Family, Mtu) -
        QUIC_DATAGRAM_OVERHEAD(CidLength) -
        QUIC_ENCRYPTION_OVERHEAD;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramInitialize(
    _In_ QUIC_DATAGRAM* Datagram
    )
{
    Datagram->Enabled = FALSE;
    Datagram->MaxLength = 0;
    Datagram->PrioritySendQueueTail = &Datagram->SendQueue;
    Datagram->SendQueueTail = &Datagram->SendQueue;
    QuicDispatchLockInitialize(&Datagram->ApiQueueLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramSetEnabledState(
    _In_ QUIC_DATAGRAM* Datagram,
    _In_ BOOLEAN Enabled
    )
{
    if (Datagram->Enabled != Enabled) {
        Datagram->Enabled = Enabled;
        QuicDatagramUpdateMaxLength(Datagram);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramIndicateSendStateChange(
    _In_ QUIC_CONNECTION* Connection,
    _Inout_ void** ClientContext,
    _In_ QUIC_DATAGRAM_SEND_STATE State
    )
{
    QUIC_CONNECTION_EVENT Event;
    Event.Type = QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED;
    Event.DATAGRAM_SEND_STATE_CHANGED.ClientContext = *ClientContext;
    Event.DATAGRAM_SEND_STATE_CHANGED.State = State;

    QuicTraceLogConnVerbose(
        DatagramSendStateChanged,
        Connection,
        "Indicating DATAGRAM_SEND_STATE_CHANGED [%p] to %u",
        *ClientContext,
        State);
    (void)QuicConnIndicateEvent(Connection, &Event);

    *ClientContext = Event.DATAGRAM_SEND_STATE_CHANGED.ClientContext;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramCancelSend(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_SEND_REQUEST* SendRequest
    )
{
    QuicDatagramIndicateSendStateChange(
        Connection,
        &SendRequest->ClientContext,
        QUIC_DATAGRAM_SEND_CANCELED);
    QuicPoolFree(&Connection->Worker->SendRequestPool, SendRequest);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramCompleteSend(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_SEND_REQUEST* SendRequest,
    _Out_opt_ void** ClientContext
    )
{
    *ClientContext = SendRequest->ClientContext;
    QuicDatagramIndicateSendStateChange(
        Connection,
        ClientContext,
        QUIC_DATAGRAM_SEND_SENT);
    QuicPoolFree(&Connection->Worker->SendRequestPool, SendRequest);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramUninitialize(
    _In_ QUIC_DATAGRAM* Datagram
    )
{
    QuicDatagramShutdown(Datagram);
    QUIC_DBG_ASSERT(Datagram->SendQueue == NULL);
    QUIC_DBG_ASSERT(Datagram->ApiQueue == NULL);
    QuicDispatchLockUninitialize(&Datagram->ApiQueueLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramShutdown(
    _In_ QUIC_DATAGRAM* Datagram
    )
{
    if (!Datagram->Enabled) {
        return;
    }

    QuicDispatchLockAcquire(&Datagram->ApiQueueLock);
    Datagram->Enabled = FALSE;
    QUIC_SEND_REQUEST* ApiQueue = Datagram->ApiQueue;
    Datagram->ApiQueue = NULL;
    QuicDispatchLockRelease(&Datagram->ApiQueueLock);

    //
    // Cancel all outstanding send requests.
    //
    QUIC_CONNECTION* Connection = QuicDatagramGetConnection(Datagram);
    while (Datagram->SendQueue != NULL) {
        QUIC_SEND_REQUEST* SendRequest = Datagram->SendQueue;
        Datagram->SendQueue = SendRequest->Next;
        QuicDatagramCancelSend(Connection, SendRequest);
    }
    Datagram->PrioritySendQueueTail = &Datagram->SendQueue;
    Datagram->SendQueueTail = &Datagram->SendQueue;

    while (ApiQueue != NULL) {
        QUIC_SEND_REQUEST* SendRequest = ApiQueue;
        ApiQueue = ApiQueue->Next;
        QuicDatagramCancelSend(Connection, SendRequest);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramUpdateMaxLength(
    _In_ QUIC_DATAGRAM* Datagram
    )
{
    QUIC_CONNECTION* Connection = QuicDatagramGetConnection(Datagram);

    uint16_t NewMaxLength;
    if (!Datagram->Enabled) {
        NewMaxLength = 0;
    } else if (!Connection->State.Started) {
        NewMaxLength =
            QuicCalculateDatagramLength(
                AF_INET6,
                QUIC_DEFAULT_PATH_MTU,
                QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH);
    } else if (Connection->PeerTransportParams.MaxDatagramFrameSize == 0) {
        NewMaxLength = 0;
    } else {
        const QUIC_PATH* Path = &Connection->Paths[0];
        NewMaxLength =
            QuicCalculateDatagramLength(
                QuicAddrGetFamily(&Path->RemoteAddress),
                Path->Mtu,
                Path->DestCid->CID.Length);
        // TODO - Take peer's MaxDatagramFrameSize into account.
    }

    if (NewMaxLength == Datagram->MaxLength) {
        return;
    }

    Datagram->MaxLength = NewMaxLength;

    QUIC_CONNECTION_EVENT Event;
    Event.Type = QUIC_CONNECTION_EVENT_DATAGRAM_MAX_LENGTH_CHANGED;
    Event.DATAGRAM_MAX_LENGTH_CHANGED.Length = NewMaxLength;

    QuicTraceLogConnVerbose(IndicateDatagramMaxLengthChanged, Connection, "Indicating DATAGRAM_MAX_LENGTH_CHANGED [%hu]", NewMaxLength);
    (void)QuicConnIndicateEvent(Connection, &Event);

    if (NewMaxLength == 0) {
        QuicDatagramShutdown(Datagram);
    } else if (Connection->State.Connected && Datagram->SendQueue != NULL) {
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_DATAGRAM);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicDatagramQueueSend(
    _In_ QUIC_DATAGRAM* Datagram,
    _In_ QUIC_SEND_REQUEST* SendRequest
    )
{
    QUIC_STATUS Status;
    BOOLEAN QueueOper = TRUE;
    QUIC_CONNECTION* Connection = QuicDatagramGetConnection(Datagram);

    QuicDispatchLockAcquire(&Datagram->ApiQueueLock);
    if (!Datagram->Enabled) {
        Status = QUIC_STATUS_INVALID_STATE;
    } else {
        QUIC_SEND_REQUEST** ApiQueueTail = &Datagram->ApiQueue;
        while (*ApiQueueTail != NULL) {
            ApiQueueTail = &((*ApiQueueTail)->Next);
            QueueOper = FALSE; // Not necessary if the previous send hasn't been flushed yet.
        }
        *ApiQueueTail = SendRequest;
        Status = QUIC_STATUS_SUCCESS;
    }
    QuicDispatchLockRelease(&Datagram->ApiQueueLock);

    if (QUIC_FAILED(Status)) {
        QuicPoolFree(&Connection->Worker->SendRequestPool, SendRequest);
        goto Exit;
    }

    if (QueueOper) {
        QUIC_OPERATION* Oper =
            QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
        if (Oper == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            QuicTraceEvent(AllocFailure, "DATAGRAM_SEND operation", 0);
            goto Exit;
        }
        Oper->API_CALL.Context->Type = QUIC_API_TYPE_DATAGRAM_SEND;

        //
        // Queue the operation but don't wait for the completion.
        //
        QuicConnQueueOper(Connection, Oper);
    }

    Status = QUIC_STATUS_PENDING;

Exit:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramSendFlush(
    _In_ QUIC_DATAGRAM* Datagram
    )
{
    QuicDispatchLockAcquire(&Datagram->ApiQueueLock);
    QUIC_SEND_REQUEST* ApiQueue = Datagram->ApiQueue;
    Datagram->ApiQueue = NULL;
    QuicDispatchLockRelease(&Datagram->ApiQueueLock);

    if (ApiQueue == NULL) {
        return;
    }

    QUIC_CONNECTION* Connection = QuicDatagramGetConnection(Datagram);
    while (ApiQueue != NULL) {

        QUIC_SEND_REQUEST* SendRequest = ApiQueue;
        ApiQueue = ApiQueue->Next;
        SendRequest->Next = NULL;

        QUIC_DBG_ASSERT(SendRequest->TotalLength != 0);
        QUIC_DBG_ASSERT(!(SendRequest->Flags & QUIC_SEND_FLAG_BUFFERED));
        QUIC_TEL_ASSERT(Datagram->Enabled);

        if (SendRequest->Flags & QUIC_SEND_FLAG_DGRAM_PRIORITY) {
            SendRequest->Next = *Datagram->PrioritySendQueueTail;
            *Datagram->PrioritySendQueueTail = SendRequest;
            if (Datagram->SendQueueTail == Datagram->PrioritySendQueueTail) {
                Datagram->SendQueueTail = &SendRequest->Next;
            }
            Datagram->PrioritySendQueueTail = &SendRequest->Next;
        } else {
            *Datagram->SendQueueTail = SendRequest;
            Datagram->SendQueueTail = &SendRequest->Next;
        }

        QuicTraceLogConnVerbose(DatagramSendQueued, Connection,
            "Datagram [%p] queued with %llu bytes (flags 0x%x)",
            SendRequest, SendRequest->TotalLength, SendRequest->Flags);
    }

    if (Connection->State.PeerTransportParameterValid) {
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_DATAGRAM);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicDatagramWriteFrame(
    _In_ QUIC_DATAGRAM* Datagram,
    _Inout_ QUIC_PACKET_BUILDER* Builder
    )
{
    QUIC_CONNECTION* Connection = QuicDatagramGetConnection(Datagram);
    QUIC_DBG_ASSERT(Datagram->Enabled);

    while (Datagram->SendQueue != NULL) {
        QUIC_SEND_REQUEST* SendRequest = Datagram->SendQueue;
        uint16_t AvailableBufferLength =
            (uint16_t)Builder->Datagram->Length - Builder->EncryptionOverhead;

        if (Builder->Metadata->Flags.KeyType == QUIC_PACKET_KEY_0_RTT &&
            !(SendRequest->Flags & QUIC_SEND_FLAG_ALLOW_0_RTT)) {
            //
            // Not allowed to send the datagram in 0-RTT.
            //
            return FALSE;
        }

        BOOLEAN HadRoomForDatagram =
            QuicDatagramFrameEncodeEx(
                SendRequest->Buffers,
                SendRequest->BufferCount,
                SendRequest->TotalLength,
                &Builder->DatagramLength,
                AvailableBufferLength,
                (uint8_t*)Builder->Datagram->Buffer);
        if (!HadRoomForDatagram && Builder->Metadata->FrameCount != 0) {
            //
            // Part of the packet was used already and we didn't have room to frame
            // this datagram. We need to try again in an unused packet.
            //
            return FALSE;
        }

        if (Datagram->PrioritySendQueueTail == &SendRequest->Next) {
            Datagram->PrioritySendQueueTail = &Datagram->SendQueue;
        }
        if (Datagram->SendQueueTail == &SendRequest->Next) {
            Datagram->SendQueueTail = &Datagram->SendQueue;
        }
        Datagram->SendQueue = SendRequest->Next;

        if (HadRoomForDatagram) {
            Builder->Metadata->Flags.IsRetransmittable = TRUE; // TODO - It's ack-eliciting but not really retransmittable
            Builder->Metadata->Frames[Builder->Metadata->FrameCount].Type = QUIC_FRAME_DATAGRAM;
            Builder->Metadata->Frames[Builder->Metadata->FrameCount].DATAGRAM.ClientContext = SendRequest->ClientContext;
            QuicDatagramCompleteSend(
                Connection,
                SendRequest,
                &Builder->Metadata->Frames[Builder->Metadata->FrameCount].DATAGRAM.ClientContext);
            if (++Builder->Metadata->FrameCount == QUIC_MAX_FRAMES_PER_PACKET) {
                return TRUE;
            }
        } else {
            QuicDatagramCancelSend(Connection, SendRequest);
        }
    }

    Connection->Send.SendFlags &= ~QUIC_CONN_SEND_FLAG_DATAGRAM;

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicDatagramProcessFrame(
    _In_ QUIC_DATAGRAM* Datagram,
    _In_ const QUIC_RECV_PACKET* const Packet,
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset
    )
{
    QUIC_DATAGRAM_EX Frame;
    if (!QuicDatagramFrameDecode(FrameType, BufferLength, Buffer, Offset, &Frame)) {
        return FALSE;
    }

    const QUIC_BUFFER QuicBuffer = { (uint16_t)Frame.Length, (uint8_t*)Frame.Data };

    QUIC_CONNECTION_EVENT Event;
    Event.Type = QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED;
    Event.DATAGRAM_RECEIVED.Buffer = &QuicBuffer;
    if (Packet->EncryptedWith0Rtt) {
        Event.DATAGRAM_RECEIVED.Flags = QUIC_RECEIVE_FLAG_0_RTT;
    } else {
        Event.DATAGRAM_RECEIVED.Flags = 0;
    }

    QUIC_CONNECTION* Connection = QuicDatagramGetConnection(Datagram);
    QuicTraceLogConnVerbose(IndicateDatagramReceived, Connection,
        "Indicating DATAGRAM_RECEIVED [len=%hu]", (uint16_t)Frame.Length);
    (void)QuicConnIndicateEvent(Connection, &Event);

    return TRUE;
}
