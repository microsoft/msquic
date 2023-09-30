/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Per path functionality for the connection.

TODO:

    Make Path ETW events.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "path.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathInitialize(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    )
{
    CxPlatZeroMemory(Path, sizeof(QUIC_PATH));
    Path->ID = Connection->NextPathId++; // TODO - Check for duplicates after wrap around?
    Path->InUse = TRUE;
    Path->MinRtt = UINT32_MAX;
    Path->Mtu = Connection->Settings.MinimumMtu;
    Path->SmoothedRtt = MS_TO_US(Connection->Settings.InitialRttMs);
    Path->RttVariance = Path->SmoothedRtt / 2;
    Path->EcnValidationState =
        Connection->Settings.EcnEnabled ? ECN_VALIDATION_TESTING : ECN_VALIDATION_FAILED;

    if (MsQuicLib.ExecutionConfig &&
        MsQuicLib.ExecutionConfig->Flags & QUIC_EXECUTION_CONFIG_FLAG_QTIP) {
        CxPlatRandom(sizeof(Path->Route.TcpState.SequenceNumber), &Path->Route.TcpState.SequenceNumber);
    }

    QuicTraceLogConnInfo(
        PathInitialized,
        Connection,
        "Path[%hhu] Initialized",
        Path->ID);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathRemove(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t Index
    )
{
    CXPLAT_DBG_ASSERT(Connection->PathsCount > 0);
    CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    if (Index >= Connection->PathsCount) {
        CXPLAT_TEL_ASSERTMSG(Index < Connection->PathsCount, "Invalid path removal!");
        return;
    }

    const QUIC_PATH* Path = &Connection->Paths[Index];
    CXPLAT_DBG_ASSERT(Path->InUse);
    QuicTraceLogConnInfo(
        PathRemoved,
        Connection,
        "Path[%hhu] Removed",
        Path->ID);

#if DEBUG
    if (Path->DestCid) {
        QUIC_CID_CLEAR_PATH(Path->DestCid);
    }
#endif

    if (Index + 1 < Connection->PathsCount) {
        CxPlatMoveMemory(
            Connection->Paths + Index,
            Connection->Paths + Index + 1,
            (Connection->PathsCount - Index - 1) * sizeof(QUIC_PATH));
    }

    Connection->PathsCount--;
    Connection->Paths[Connection->PathsCount].InUse = FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetAllowance(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ uint32_t NewAllowance
    )
{
    Path->Allowance = NewAllowance;
    BOOLEAN IsBlocked = Path->Allowance < QUIC_MIN_SEND_ALLOWANCE;

    if (!Path->IsPeerValidated) {
        if (!IsBlocked) {
            if (QuicConnRemoveOutFlowBlockedReason(
                    Connection, QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT)) {

                if (Connection->Send.SendFlags != 0) {
                    //
                    // We were blocked by amplification protection (no allowance
                    // left) and we have stuff to send, so flush the send now.
                    //
                    QuicSendQueueFlush(&Connection->Send, REASON_AMP_PROTECTION);
                }

                //
                // Now that we are no longer blocked by amplification protection
                // we need to re-enable the loss detection timers. This call may
                // even cause the loss timer to fire immediately because packets
                // were already lost, but we didn't know it.
                //
                QuicLossDetectionUpdateTimer(&Connection->LossDetection, TRUE);
            }

        } else {
            QuicConnAddOutFlowBlockedReason(
                Connection, QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetValid(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_PATH_VALID_REASON Reason
    )
{
    if (Path->IsPeerValidated) {
        return;
    }

    const char* ReasonStrings[] = {
        "Initial Token",
        "Handshake Packet",
        "Path Response"
    };

    QuicTraceLogConnInfo(
        PathValidated,
        Connection,
        "Path[%hhu] Validated (%s)",
        Path->ID,
        ReasonStrings[Reason]);

    Path->IsPeerValidated = TRUE;
    QuicPathSetAllowance(Connection, Path, UINT32_MAX);

    if (Reason == QUIC_PATH_VALID_PATH_RESPONSE) {
        //
        // If the active path was just validated, then let's queue up DPLPMTUD.
        // This will force validate min mtu if it has not already been
        // validated.
        //
        QuicMtuDiscoveryPeerValidated(&Path->MtuDiscovery, Connection);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
_Success_(return != NULL)
QUIC_PATH*
QuicConnGetPathByID(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t ID,
    _Out_ uint8_t* Index
    )
{
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (Connection->Paths[i].ID == ID) {
            *Index = i;
            return &Connection->Paths[i];
        }
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
QUIC_PATH*
QuicConnGetPathForPacket(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_RX_PACKET* Packet
    )
{
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (!QuicAddrCompare(
                &Packet->Route->LocalAddress,
                &Connection->Paths[i].Route.LocalAddress) ||
            !QuicAddrCompare(
                &Packet->Route->RemoteAddress,
                &Connection->Paths[i].Route.RemoteAddress)) {
            if (!Connection->State.HandshakeConfirmed) {
                //
                // Ignore packets on any other paths until connected/confirmed.
                //
                return NULL;
            }
            continue;
        }
        return &Connection->Paths[i];
    }

    if (Connection->PathsCount == QUIC_MAX_PATH_COUNT) {
        //
        // See if any old paths share the same remote address, and is just a rebind.
        // If so, remove the old paths.
        // NB: Traversing the array backwards is simpler and more efficient here due
        // to the array shifting that happens in QuicPathRemove.
        //
        for (uint8_t i = Connection->PathsCount - 1; i > 0; i--) {
            if (!Connection->Paths[i].IsActive
                && QuicAddrGetFamily(&Packet->Route->RemoteAddress) == QuicAddrGetFamily(&Connection->Paths[i].Route.RemoteAddress)
                && QuicAddrCompareIp(&Packet->Route->RemoteAddress, &Connection->Paths[i].Route.RemoteAddress)
                && QuicAddrCompare(&Packet->Route->LocalAddress, &Connection->Paths[i].Route.LocalAddress)) {
                QuicPathRemove(Connection, i);
            }
        }

        if (Connection->PathsCount == QUIC_MAX_PATH_COUNT) {
            //
            // Already tracking the maximum number of paths, and can't free
            // any more.
            //
            return NULL;
        }
    }

    if (Connection->PathsCount > 1) {
        //
        // Make room for the new path (at index 1).
        //
        CxPlatMoveMemory(
            &Connection->Paths[2],
            &Connection->Paths[1],
            (Connection->PathsCount - 1) * sizeof(QUIC_PATH));
    }

    CXPLAT_DBG_ASSERT(Connection->PathsCount < QUIC_MAX_PATH_COUNT);
    QUIC_PATH* Path = &Connection->Paths[1];
    QuicPathInitialize(Connection, Path);
    Connection->PathsCount++;

    if (Connection->Paths[0].DestCid->CID.Length == 0) {
        Path->DestCid = Connection->Paths[0].DestCid; // TODO - Copy instead?
    }
    Path->Binding = Connection->Paths[0].Binding;
    QuicCopyRouteInfo(&Path->Route, Packet->Route);
    QuicPathValidate(Path);

    return Path;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetActive(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    )
{
    BOOLEAN UdpPortChangeOnly = FALSE;
    if (Path == &Connection->Paths[0]) {
        CXPLAT_DBG_ASSERT(!Path->IsActive);
        Path->IsActive = TRUE;
    } else {
        CXPLAT_DBG_ASSERT(Path->DestCid != NULL);
        UdpPortChangeOnly =
            QuicAddrGetFamily(&Path->Route.RemoteAddress) == QuicAddrGetFamily(&Connection->Paths[0].Route.RemoteAddress) &&
            QuicAddrCompareIp(&Path->Route.RemoteAddress, &Connection->Paths[0].Route.RemoteAddress);

        QUIC_PATH PrevActivePath = Connection->Paths[0];

        PrevActivePath.IsActive = FALSE;
        Path->IsActive = TRUE;
        if (UdpPortChangeOnly) {
            //
            // We assume port only changes don't change the PMTU.
            //
            Path->IsMinMtuValidated = PrevActivePath.IsMinMtuValidated;
        }

        Connection->Paths[0] = *Path;
        *Path = PrevActivePath;
    }

    QuicTraceLogConnInfo(
        PathActive,
        Connection,
        "Path[%hhu] Set active (rebind=%hhu)",
        Connection->Paths[0].ID,
        UdpPortChangeOnly);

    if (!UdpPortChangeOnly) {
        QuicCongestionControlReset(&Connection->CongestionControl, FALSE);
    }
    CXPLAT_DBG_ASSERT(Path->DestCid != NULL);
    CXPLAT_DBG_ASSERT(!Path->DestCid->CID.Retired);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathUpdateQeo(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ CXPLAT_QEO_OPERATION Operation
    )
{
    const QUIC_CID_HASH_ENTRY* SourceCid =
        CXPLAT_CONTAINING_RECORD(Connection->SourceCids.Next, QUIC_CID_HASH_ENTRY, Link);
    CXPLAT_QEO_CONNECTION Offloads[2] = {
    {
        Operation,
        CXPLAT_QEO_DIRECTION_TRANSMIT,
        CXPLAT_QEO_DECRYPT_FAILURE_ACTION_DROP,
        0, // KeyPhase
        0, // Reserved
        CXPLAT_QEO_CIPHER_TYPE_AEAD_AES_256_GCM,
        Connection->Send.NextPacketNumber,
        Path->Route.RemoteAddress,
        Path->DestCid->CID.Length,
    },
    {
        Operation,
        CXPLAT_QEO_DIRECTION_RECEIVE,
        CXPLAT_QEO_DECRYPT_FAILURE_ACTION_DROP,
        0, // KeyPhase
        0, // Reserved
        CXPLAT_QEO_CIPHER_TYPE_AEAD_AES_256_GCM,
        0, // NextPacketNumber
        Path->Route.LocalAddress,
        SourceCid->CID.Length,
    }};
    CxPlatCopyMemory(Offloads[0].ConnectionId, Path->DestCid->CID.Data, Path->DestCid->CID.Length);
    CxPlatCopyMemory(Offloads[1].ConnectionId, SourceCid->CID.Data, SourceCid->CID.Length);

    if (Operation == CXPLAT_QEO_OPERATION_ADD) {
        CXPLAT_DBG_ASSERT(Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]);
        Offloads[0].KeyPhase = Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]->CurrentKeyPhase;
        Offloads[1].KeyPhase = Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]->CurrentKeyPhase;
        Offloads[1].NextPacketNumber = Connection->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]->AckTracker.LargestPacketNumberAcknowledged;
        if (QuicTlsPopulateOffloadKeys(Connection->Crypto.TLS, Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT], "Tx offload", &Offloads[0]) &&
            QuicTlsPopulateOffloadKeys(Connection->Crypto.TLS, Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_1_RTT],  "Rx offload", &Offloads[1]) &&
            QUIC_SUCCEEDED(CxPlatSocketUpdateQeo(Path->Binding->Socket, Offloads, 2))) {
            Connection->Stats.EncryptionOffloaded = TRUE;
            Path->EncryptionOffloading = TRUE;
            QuicTraceLogConnInfo(
                PathQeoEnabled,
                Connection,
                "Path[%hhu] QEO enabled",
                Path->ID);
        }
        CxPlatSecureZeroMemory(Offloads, sizeof(Offloads));
    } else {
        CXPLAT_DBG_ASSERT(Path->EncryptionOffloading);
        (void)CxPlatSocketUpdateQeo(Path->Binding->Socket, Offloads, 2);
        Path->EncryptionOffloading = FALSE;
        QuicTraceLogConnInfo(
            PathQeoDisabled,
            Connection,
            "Path[%hhu] QEO disabled",
            Path->ID);
    }
}
