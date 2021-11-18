/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Manages the unreliable datagram feature's functionality for a connection.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "datagram.c.clog.h"
#endif

#define DATAGRAM_FRAME_HEADER_LENGTH 3

#define QUIC_DATAGRAM_OVERHEAD(CidLength) \
(\
    MIN_SHORT_HEADER_LENGTH_V1 + \
    (CidLength) + \
    DATAGRAM_FRAME_HEADER_LENGTH \
)

#if DEBUG
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramValidate(
    _In_ const QUIC_DATAGRAM* Datagram
    )
{
    QUIC_CONNECTION* Connection = QuicDatagramGetConnection(Datagram);
    //
    // If a datagram is to be sent down the connection, the datagram must have
    // items in its queue. Otherwise, sending will have an error case.
    //
    if (QuicConnIsClosed(Connection)) {
        CXPLAT_DBG_ASSERT(Datagram->SendQueue == NULL);
        CXPLAT_DBG_ASSERT((Connection->Send.SendFlags & QUIC_CONN_SEND_FLAG_DATAGRAM) == 0);
    } else if ((Connection->Send.SendFlags & QUIC_CONN_SEND_FLAG_DATAGRAM) != 0) {
        CXPLAT_DBG_ASSERT(Datagram->SendQueue != NULL);
    } else if (Connection->State.PeerTransportParameterValid) {
        CXPLAT_DBG_ASSERT(Datagram->SendQueue == NULL);
    }

    if (!Datagram->SendEnabled) {
        CXPLAT_DBG_ASSERT(Datagram->MaxSendLength == 0);
    } else {
        QUIC_SEND_REQUEST* SendRequest = Datagram->SendQueue;
        while (SendRequest) {
            CXPLAT_DBG_ASSERT(SendRequest->TotalLength <= (uint64_t)Datagram->MaxSendLength);
            SendRequest = SendRequest->Next;
        }
    }
}
#else
#define QuicDatagramValidate(Datagram)
#endif

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
        CXPLAT_ENCRYPTION_OVERHEAD;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramInitialize(
    _In_ QUIC_DATAGRAM* Datagram
    )
{
    Datagram->SendEnabled = TRUE;
    Datagram->MaxSendLength = UINT16_MAX;
    Datagram->PrioritySendQueueTail = &Datagram->SendQueue;
    Datagram->SendQueueTail = &Datagram->SendQueue;
    CxPlatDispatchLockInitialize(&Datagram->ApiQueueLock);
    QuicDatagramValidate(Datagram);
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
        "Indicating DATAGRAM_SEND_STATE_CHANGED to %u",
        (uint32_t)State);
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
    CxPlatPoolFree(&Connection->Worker->SendRequestPool, SendRequest);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramCompleteSend(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_SEND_REQUEST* SendRequest,
    _Out_ void** ClientContext
    )
{
    CxPlatCopyMemory(ClientContext, &SendRequest->ClientContext, sizeof(*ClientContext));
    QuicDatagramIndicateSendStateChange(
        Connection,
        ClientContext,
        QUIC_DATAGRAM_SEND_SENT);
    CxPlatPoolFree(&Connection->Worker->SendRequestPool, SendRequest);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramUninitialize(
    _In_ QUIC_DATAGRAM* Datagram
    )
{
    QuicDatagramSendShutdown(Datagram);
    CXPLAT_DBG_ASSERT(Datagram->SendQueue == NULL);
    CXPLAT_DBG_ASSERT(Datagram->ApiQueue == NULL);
    CxPlatDispatchLockUninitialize(&Datagram->ApiQueueLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramSendShutdown(
    _In_ QUIC_DATAGRAM* Datagram
    )
{
    if (!Datagram->SendEnabled) {
        return;
    }

    QUIC_CONNECTION* Connection = QuicDatagramGetConnection(Datagram);

    QuicTraceLogConnVerbose(
        DatagramSendShutdown,
        Connection,
        "Datagram send shutdown");

    CxPlatDispatchLockAcquire(&Datagram->ApiQueueLock);
    Datagram->SendEnabled = FALSE;
    Datagram->MaxSendLength = 0;
    QUIC_SEND_REQUEST* ApiQueue = Datagram->ApiQueue;
    Datagram->ApiQueue = NULL;
    CxPlatDispatchLockRelease(&Datagram->ApiQueueLock);

    QuicSendClearSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_DATAGRAM);

    //
    // Cancel all outstanding send requests.
    //
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

    QuicDatagramValidate(Datagram);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramOnMaxSendLengthChanged(
    _In_ QUIC_DATAGRAM* Datagram
    )
{
    QUIC_CONNECTION* Connection = QuicDatagramGetConnection(Datagram);

    //
    // Cancel any outstanding requests that might not fit any more.
    //
    QUIC_SEND_REQUEST** SendQueue = &Datagram->SendQueue;
    while (*SendQueue != NULL) {
        if ((*SendQueue)->TotalLength > (uint64_t)Datagram->MaxSendLength) {
            QUIC_SEND_REQUEST* SendRequest = *SendQueue;
            if (Datagram->PrioritySendQueueTail == &SendRequest->Next) {
                Datagram->PrioritySendQueueTail = SendQueue;
            }
            *SendQueue = SendRequest->Next;
            QuicDatagramCancelSend(Connection, SendRequest);
        } else {
            SendQueue = &((*SendQueue)->Next);
        }
    }
    Datagram->SendQueueTail = SendQueue;

    if (Datagram->SendQueue != NULL) {
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_DATAGRAM);
    } else {
        QuicSendClearSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_DATAGRAM);
    }

    QuicDatagramValidate(Datagram);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramOnSendStateChanged(
    _In_ QUIC_DATAGRAM* Datagram
    )
{
    QUIC_CONNECTION* Connection = QuicDatagramGetConnection(Datagram);

    //
    // Until we receive the peer's transport parameters, we assume that
    // datagrams are enabled, with unlimited max length. This allows for the
    // app to still queue datagrams. We won't actually send them out until we
    // have received the peer's transport parameters (either from a 0-RTT cache
    // or during the handshake). If, when we do receive the transport
    // parameters, we find that the feature is disabled or any of the queued
    // datagrams are too long, then we will cancel and indicate state changes
    // to the app, as appropriate.
    //

    BOOLEAN SendEnabled = TRUE;
    uint16_t NewMaxSendLength = UINT16_MAX;
    if (Connection->State.PeerTransportParameterValid) {
        if (!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_MAX_DATAGRAM_FRAME_SIZE)) {
            SendEnabled = FALSE;
            NewMaxSendLength = 0;
        } else {
            if (Connection->PeerTransportParams.MaxDatagramFrameSize < UINT16_MAX) {
                NewMaxSendLength = (uint16_t)Connection->PeerTransportParams.MaxDatagramFrameSize;
            }
        }
    }

    if (SendEnabled) {
        uint16_t MtuMaxSendLength;
        if (!Connection->State.Started) {
            MtuMaxSendLength =
                QuicCalculateDatagramLength(
                    QUIC_ADDRESS_FAMILY_INET6,
                    QUIC_DPLPMUTD_MIN_MTU,
                    QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH);
        } else {
            const QUIC_PATH* Path = &Connection->Paths[0];
            MtuMaxSendLength =
                QuicCalculateDatagramLength(
                    QuicAddrGetFamily(&Path->Route.RemoteAddress),
                    Path->Mtu,
                    Path->DestCid->CID.Length);
        }
        if (NewMaxSendLength > MtuMaxSendLength) {
            NewMaxSendLength = MtuMaxSendLength;
        }
    }

    if (SendEnabled == Datagram->SendEnabled) {
        if (!SendEnabled || NewMaxSendLength == Datagram->MaxSendLength) {
            return;
        }
    }

    Datagram->MaxSendLength = NewMaxSendLength;

    if (Connection->State.ExternalOwner) {
        QUIC_CONNECTION_EVENT Event;
        Event.Type = QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED;
        Event.DATAGRAM_STATE_CHANGED.SendEnabled = SendEnabled;
        Event.DATAGRAM_STATE_CHANGED.MaxSendLength = NewMaxSendLength;

        QuicTraceLogConnVerbose(
            IndicateDatagramStateChanged,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED [SendEnabled=%hhu] [MaxSendLength=%hu]",
            Event.DATAGRAM_STATE_CHANGED.SendEnabled,
            Event.DATAGRAM_STATE_CHANGED.MaxSendLength);
        (void)QuicConnIndicateEvent(Connection, &Event);
    }

    if (!SendEnabled) {
        QuicDatagramSendShutdown(Datagram);
    } else {
        if (!Datagram->SendEnabled) {
            Datagram->SendEnabled = TRUE; // This can happen for 0-RTT connections that didn't previously support Datagrams
        }
        QuicDatagramOnMaxSendLengthChanged(Datagram);
    }

    QuicDatagramValidate(Datagram);
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

    CxPlatDispatchLockAcquire(&Datagram->ApiQueueLock);
    if (!Datagram->SendEnabled) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Datagram send while disabled");
        Status = QUIC_STATUS_INVALID_STATE;
    } else {
        if (SendRequest->TotalLength > (uint64_t)Datagram->MaxSendLength) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Datagram send request is longer than allowed");
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            QUIC_SEND_REQUEST** ApiQueueTail = &Datagram->ApiQueue;
            while (*ApiQueueTail != NULL) {
                ApiQueueTail = &((*ApiQueueTail)->Next);
                QueueOper = FALSE; // Not necessary if the previous send hasn't been flushed yet.
            }
            *ApiQueueTail = SendRequest;
            Status = QUIC_STATUS_SUCCESS;
        }
    }
    CxPlatDispatchLockRelease(&Datagram->ApiQueueLock);

    if (QUIC_FAILED(Status)) {
        CxPlatPoolFree(&Connection->Worker->SendRequestPool, SendRequest);
        goto Exit;
    }

    if (QueueOper) {
        QUIC_OPERATION* Oper =
            QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
        if (Oper == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "DATAGRAM_SEND operation",
                0);
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
    CxPlatDispatchLockAcquire(&Datagram->ApiQueueLock);
    QUIC_SEND_REQUEST* ApiQueue = Datagram->ApiQueue;
    Datagram->ApiQueue = NULL;
    CxPlatDispatchLockRelease(&Datagram->ApiQueueLock);
    uint64_t TotalBytesSent = 0;

    if (ApiQueue == NULL) {
        return;
    }

    QUIC_CONNECTION* Connection = QuicDatagramGetConnection(Datagram);
    while (ApiQueue != NULL) {

        QUIC_SEND_REQUEST* SendRequest = ApiQueue;
        ApiQueue = ApiQueue->Next;
        SendRequest->Next = NULL;

        CXPLAT_DBG_ASSERT(!(SendRequest->Flags & QUIC_SEND_FLAG_BUFFERED));
        CXPLAT_TEL_ASSERT(Datagram->SendEnabled);

        if (SendRequest->TotalLength > (uint64_t)Datagram->MaxSendLength || QuicConnIsClosed(Connection)) {
            QuicDatagramCancelSend(Connection, SendRequest);
            continue;
        }
        TotalBytesSent += SendRequest->TotalLength;

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

        QuicTraceLogConnVerbose(
            DatagramSendQueued,
            Connection,
            "Datagram [%p] queued with %llu bytes (flags 0x%x)",
            SendRequest,
            SendRequest->TotalLength,
            SendRequest->Flags);
    }

    if (Connection->State.PeerTransportParameterValid && Datagram->SendQueue != NULL) {
        CXPLAT_DBG_ASSERT(Datagram->SendEnabled);
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_DATAGRAM);
    }

    QuicDatagramValidate(Datagram);
    QuicPerfCounterAdd(QUIC_PERF_COUNTER_APP_SEND_BYTES, TotalBytesSent);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicDatagramWriteFrame(
    _In_ QUIC_DATAGRAM* Datagram,
    _Inout_ QUIC_PACKET_BUILDER* Builder
    )
{
    QUIC_CONNECTION* Connection = QuicDatagramGetConnection(Datagram);
    CXPLAT_DBG_ASSERT(Datagram->SendEnabled);
    BOOLEAN Result = FALSE;

    QuicDatagramValidate(Datagram);

    while (Datagram->SendQueue != NULL) {
        QUIC_SEND_REQUEST* SendRequest = Datagram->SendQueue;

        if (Builder->Metadata->Flags.KeyType == QUIC_PACKET_KEY_0_RTT &&
            !(SendRequest->Flags & QUIC_SEND_FLAG_ALLOW_0_RTT)) {
            CXPLAT_DBG_ASSERT(FALSE);
            Result = FALSE;
            goto Exit; // This datagram isn't allowed in 0-RTT.
        }

        CXPLAT_DBG_ASSERT(SendRequest->TotalLength <= Datagram->MaxSendLength);

        uint16_t AvailableBufferLength =
            (uint16_t)Builder->Datagram->Length - Builder->EncryptionOverhead;

        BOOLEAN HadRoomForDatagram =
            QuicDatagramFrameEncodeEx(
                SendRequest->Buffers,
                SendRequest->BufferCount,
                SendRequest->TotalLength,
                &Builder->DatagramLength,
                AvailableBufferLength,
                Builder->Datagram->Buffer);
        if (!HadRoomForDatagram) {
            //
            // We didn't have room to frame this datagram. This should only
            // happen if there was other data in the packet already. Otherwise
            // it means we have a bug where we allowed a datagram to be queued
            // (or stay queued, after max length changed) that was too big.
            //
            CXPLAT_DBG_ASSERT(
                Builder->Datagram->Length < Datagram->MaxSendLength ||
                Builder->Metadata->FrameCount != 0 ||
                Builder->PacketStart != 0);
            Result = TRUE;
            goto Exit;
        }

        if (Datagram->PrioritySendQueueTail == &SendRequest->Next) {
            Datagram->PrioritySendQueueTail = &Datagram->SendQueue;
        }
        if (Datagram->SendQueueTail == &SendRequest->Next) {
            Datagram->SendQueueTail = &Datagram->SendQueue;
        }
        Datagram->SendQueue = SendRequest->Next;

        Builder->Metadata->Flags.IsAckEliciting = TRUE;
        Builder->Metadata->Frames[Builder->Metadata->FrameCount].Type = QUIC_FRAME_DATAGRAM;
        Builder->Metadata->Frames[Builder->Metadata->FrameCount].DATAGRAM.ClientContext = SendRequest->ClientContext;
        QuicDatagramCompleteSend(
            Connection,
            SendRequest,
            &Builder->Metadata->Frames[Builder->Metadata->FrameCount].DATAGRAM.ClientContext);
        if (++Builder->Metadata->FrameCount == QUIC_MAX_FRAMES_PER_PACKET) {
            Result = TRUE;
            goto Exit;
        }
    }

Exit:
    if (Datagram->SendQueue == NULL) {
        Connection->Send.SendFlags &= ~QUIC_CONN_SEND_FLAG_DATAGRAM;
    }

    QuicDatagramValidate(Datagram);

    return Result;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicDatagramProcessFrame(
    _In_ QUIC_DATAGRAM* Datagram,
    _In_ const CXPLAT_RECV_PACKET* const Packet,
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset
    )
{
    QUIC_CONNECTION* Connection = QuicDatagramGetConnection(Datagram);
    CXPLAT_DBG_ASSERT(Connection->Settings.DatagramReceiveEnabled);

    QUIC_DATAGRAM_EX Frame;
    if (!QuicDatagramFrameDecode(FrameType, BufferLength, Buffer, Offset, &Frame)) {
        return FALSE;
    }

    // TODO - If we ever limit max receive length, validate it here.

    const QUIC_BUFFER QuicBuffer = { (uint16_t)Frame.Length, (uint8_t*)Frame.Data };

    QUIC_CONNECTION_EVENT Event;
    Event.Type = QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED;
    Event.DATAGRAM_RECEIVED.Buffer = &QuicBuffer;
    if (Packet->EncryptedWith0Rtt) {
        Event.DATAGRAM_RECEIVED.Flags = QUIC_RECEIVE_FLAG_0_RTT;
    } else {
        Event.DATAGRAM_RECEIVED.Flags = 0;
    }

    QuicTraceLogConnVerbose(
        IndicateDatagramReceived,
        Connection,
        "Indicating DATAGRAM_RECEIVED [len=%hu]",
        (uint16_t)Frame.Length);
    (void)QuicConnIndicateEvent(Connection, &Event);

    QuicPerfCounterAdd(QUIC_PERF_COUNTER_APP_RECV_BYTES, QuicBuffer.Length);

    return TRUE;
}
