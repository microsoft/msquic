/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The per UDP binding (local IP/port and optionally remote IP) state. This
    includes the lookup state for processing a received packet and the list of
    listeners registered.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "binding.c.clog.h"
#endif

//
// Make sure we will always have enough room to fit our Version Negotiation packet,
// which includes both the global, constant list of supported versions and the
// randomly generated version.
//
#define MAX_VER_NEG_PACKET_LENGTH \
( \
    sizeof(QUIC_VERSION_NEGOTIATION_PACKET) + \
    QUIC_MAX_CONNECTION_ID_LENGTH_INVARIANT + \
    QUIC_MAX_CONNECTION_ID_LENGTH_INVARIANT + \
    sizeof(uint32_t) + \
    (ARRAYSIZE(QuicSupportedVersionList) * sizeof(uint32_t)) \
)
CXPLAT_STATIC_ASSERT(
    QUIC_DPLPMUTD_MIN_MTU - 48 >= MAX_VER_NEG_PACKET_LENGTH,
    "Too many supported version numbers! Requires too big of buffer for response!");

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicBindingInitialize(
    _In_ const CXPLAT_UDP_CONFIG* UdpConfig,
    _Out_ QUIC_BINDING** NewBinding
    )
{
    QUIC_STATUS Status;
    QUIC_BINDING* Binding;
    BOOLEAN HashTableInitialized = FALSE;

    Binding = CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_BINDING), QUIC_POOL_BINDING);
    if (Binding == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_BINDING",
            sizeof(QUIC_BINDING));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Binding->RefCount = 0; // No refs until it's added to the library's list
    Binding->Exclusive = !(UdpConfig->Flags & CXPLAT_SOCKET_FLAG_SHARE);
    Binding->ServerOwned = !!(UdpConfig->Flags & CXPLAT_SOCKET_SERVER_OWNED);
    Binding->Connected = UdpConfig->RemoteAddress == NULL ? FALSE : TRUE;
    Binding->StatelessOperCount = 0;
    CxPlatDispatchRwLockInitialize(&Binding->RwLock);
    CxPlatDispatchLockInitialize(&Binding->StatelessOperLock);
    CxPlatListInitializeHead(&Binding->Listeners);
    QuicLookupInitialize(&Binding->Lookup);
    if (!CxPlatHashtableInitializeEx(&Binding->StatelessOperTable, CXPLAT_HASH_MIN_SIZE)) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    HashTableInitialized = TRUE;
    CxPlatListInitializeHead(&Binding->StatelessOperList);

    //
    // Random reserved version number for version negotation.
    //
    CxPlatRandom(sizeof(uint32_t), &Binding->RandomReservedVersion);
    Binding->RandomReservedVersion =
        (Binding->RandomReservedVersion & ~QUIC_VERSION_RESERVED_MASK) |
        QUIC_VERSION_RESERVED;

#ifdef QUIC_COMPARTMENT_ID
    Binding->CompartmentId = UdpConfig->CompartmentId;

    BOOLEAN RevertCompartmentId = FALSE;
    QUIC_COMPARTMENT_ID PrevCompartmentId = QuicCompartmentIdGetCurrent();
    if (PrevCompartmentId != UdpConfig->CompartmentId) {
        Status = QuicCompartmentIdSetCurrent(UdpConfig->CompartmentId);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                BindingErrorStatus,
                "[bind][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "Set current compartment Id");
            goto Error;
        }
        RevertCompartmentId = TRUE;
    }
#endif

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    QUIC_TEST_DATAPATH_HOOKS* Hooks = MsQuicLib.TestDatapathHooks;
    CXPLAT_UDP_CONFIG HookUdpConfig = *UdpConfig;
    if (Hooks != NULL) {
        QUIC_ADDR RemoteAddressCopy;
        if (UdpConfig->RemoteAddress != NULL) {
            RemoteAddressCopy = *UdpConfig->RemoteAddress;
        }
        QUIC_ADDR LocalAddressCopy;
        if (UdpConfig->LocalAddress != NULL) {
            LocalAddressCopy = *UdpConfig->LocalAddress;
        }
        Hooks->Create(
            UdpConfig->RemoteAddress != NULL ? &RemoteAddressCopy : NULL,
            UdpConfig->LocalAddress != NULL ? &LocalAddressCopy : NULL);

        HookUdpConfig.LocalAddress = (UdpConfig->LocalAddress != NULL) ? &LocalAddressCopy : NULL;
        HookUdpConfig.RemoteAddress = (UdpConfig->RemoteAddress != NULL) ? &RemoteAddressCopy : NULL;
        HookUdpConfig.CallbackContext = Binding;

        Status =
            CxPlatSocketCreateUdp(
                MsQuicLib.Datapath,
                &HookUdpConfig,
                &Binding->Socket);
    } else {
#endif
        ((CXPLAT_UDP_CONFIG*)UdpConfig)->CallbackContext = Binding;

        Status =
            CxPlatSocketCreateUdp(
                MsQuicLib.Datapath,
                UdpConfig,
                &Binding->Socket);
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    }
#endif

#ifdef QUIC_COMPARTMENT_ID
    if (RevertCompartmentId) {
        (void)QuicCompartmentIdSetCurrent(PrevCompartmentId);
    }
#endif

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            BindingErrorStatus,
            "[bind][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Create datapath binding");
        goto Error;
    }

    QUIC_ADDR DatapathLocalAddr, DatapathRemoteAddr;
    QuicBindingGetLocalAddress(Binding, &DatapathLocalAddr);
    QuicBindingGetRemoteAddress(Binding, &DatapathRemoteAddr);
    QuicTraceEvent(
        BindingCreated,
        "[bind][%p] Created, Udp=%p LocalAddr=%!ADDR! RemoteAddr=%!ADDR!",
        Binding,
        Binding->Socket,
        CASTED_CLOG_BYTEARRAY(sizeof(DatapathLocalAddr), &DatapathLocalAddr),
        CASTED_CLOG_BYTEARRAY(sizeof(DatapathRemoteAddr), &DatapathRemoteAddr));

    *NewBinding = Binding;
    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        if (Binding != NULL) {
            QuicLookupUninitialize(&Binding->Lookup);
            if (HashTableInitialized) {
                CxPlatHashtableUninitialize(&Binding->StatelessOperTable);
            }
            CxPlatDispatchLockUninitialize(&Binding->StatelessOperLock);
            CxPlatDispatchRwLockUninitialize(&Binding->RwLock);
            CXPLAT_FREE(Binding, QUIC_POOL_BINDING);
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicBindingUninitialize(
    _In_ QUIC_BINDING* Binding
    )
{
    QuicTraceEvent(
        BindingCleanup,
        "[bind][%p] Cleaning up",
        Binding);

    CXPLAT_TEL_ASSERT(Binding->RefCount == 0);
    CXPLAT_TEL_ASSERT(CxPlatListIsEmpty(&Binding->Listeners));

    //
    // Delete the datapath binding. This function blocks until all receive
    // upcalls have completed.
    //
    CxPlatSocketDelete(Binding->Socket);

    //
    // Clean up any leftover stateless operations being tracked.
    //
    while (!CxPlatListIsEmpty(&Binding->StatelessOperList)) {
        QUIC_STATELESS_CONTEXT* StatelessCtx =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&Binding->StatelessOperList),
                QUIC_STATELESS_CONTEXT,
                ListEntry);
        Binding->StatelessOperCount--;
        CxPlatHashtableRemove(
            &Binding->StatelessOperTable,
            &StatelessCtx->TableEntry,
            NULL);
        CXPLAT_DBG_ASSERT(StatelessCtx->IsProcessed);
        CxPlatPoolFree(
            &StatelessCtx->Worker->StatelessContextPool,
            StatelessCtx);
    }
    CXPLAT_DBG_ASSERT(Binding->StatelessOperCount == 0);
    CXPLAT_DBG_ASSERT(Binding->StatelessOperTable.NumEntries == 0);

    QuicLookupUninitialize(&Binding->Lookup);
    CxPlatDispatchLockUninitialize(&Binding->StatelessOperLock);
    CxPlatHashtableUninitialize(&Binding->StatelessOperTable);
    CxPlatDispatchRwLockUninitialize(&Binding->RwLock);

    QuicTraceEvent(
        BindingDestroyed,
        "[bind][%p] Destroyed",
        Binding);
    CXPLAT_FREE(Binding, QUIC_POOL_BINDING);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingTraceRundown(
    _In_ QUIC_BINDING* Binding
    )
{
    // TODO - Trace datapath binding

    QUIC_ADDR DatapathLocalAddr, DatapathRemoteAddr;
    QuicBindingGetLocalAddress(Binding, &DatapathLocalAddr);
    QuicBindingGetRemoteAddress(Binding, &DatapathRemoteAddr);
    QuicTraceEvent(
        BindingRundown,
        "[bind][%p] Rundown, Udp=%p LocalAddr=%!ADDR! RemoteAddr=%!ADDR!",
        Binding,
        Binding->Socket,
        CASTED_CLOG_BYTEARRAY(sizeof(DatapathLocalAddr), &DatapathLocalAddr),
        CASTED_CLOG_BYTEARRAY(sizeof(DatapathRemoteAddr), &DatapathRemoteAddr));

    CxPlatDispatchRwLockAcquireShared(&Binding->RwLock);

    for (CXPLAT_LIST_ENTRY* Link = Binding->Listeners.Flink;
        Link != &Binding->Listeners;
        Link = Link->Flink) {
        QuicListenerTraceRundown(
            CXPLAT_CONTAINING_RECORD(Link, QUIC_LISTENER, Link));
    }

    CxPlatDispatchRwLockReleaseShared(&Binding->RwLock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingGetLocalAddress(
    _In_ QUIC_BINDING* Binding,
    _Out_ QUIC_ADDR* Address
    )
{
    CxPlatSocketGetLocalAddress(Binding->Socket, Address);
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    QUIC_TEST_DATAPATH_HOOKS* Hooks = MsQuicLib.TestDatapathHooks;
    if (Hooks != NULL) {
        Hooks->GetLocalAddress(Address);
    }
#endif
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingGetRemoteAddress(
    _In_ QUIC_BINDING* Binding,
    _Out_ QUIC_ADDR* Address
    )
{
    CxPlatSocketGetRemoteAddress(Binding->Socket, Address);
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    QUIC_TEST_DATAPATH_HOOKS* Hooks = MsQuicLib.TestDatapathHooks;
    if (Hooks != NULL) {
        Hooks->GetRemoteAddress(Address);
    }
#endif
}

//
// Returns TRUE if there are any registered listeners on this binding.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicBindingHasListenerRegistered(
    _In_ const QUIC_BINDING* const Binding
    )
{
    return !CxPlatListIsEmpty(&Binding->Listeners);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicBindingRegisterListener(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_LISTENER* NewListener
    )
{
    BOOLEAN AddNewListener = TRUE;
    BOOLEAN MaximizeLookup = FALSE;

    const QUIC_ADDR* NewAddr = &NewListener->LocalAddress;
    const BOOLEAN NewWildCard = NewListener->WildCard;
    const QUIC_ADDRESS_FAMILY NewFamily = QuicAddrGetFamily(NewAddr);

    CxPlatDispatchRwLockAcquireExclusive(&Binding->RwLock);

    //
    // For a single binding, listeners are saved in a linked list, sorted by
    // family first, in decending order {AF_INET6, AF_INET, AF_UNSPEC}, and then
    // specific addresses followed by wild card addresses. Insertion of a new
    // listener with a given IP/ALPN go at the end of the existing family group,
    // only if there isn't a direct match prexisting in the list.
    //

    CXPLAT_LIST_ENTRY* Link;
    for (Link = Binding->Listeners.Flink;
        Link != &Binding->Listeners;
        Link = Link->Flink) {

        const QUIC_LISTENER* ExistingListener =
            CXPLAT_CONTAINING_RECORD(Link, QUIC_LISTENER, Link);
        const QUIC_ADDR* ExistingAddr = &ExistingListener->LocalAddress;
        const BOOLEAN ExistingWildCard = ExistingListener->WildCard;
        const QUIC_ADDRESS_FAMILY ExistingFamily = QuicAddrGetFamily(ExistingAddr);

        if (NewFamily > ExistingFamily) {
            break; // End of possible family matches. Done searching.
        }

        if (NewFamily != ExistingFamily) {
            continue;
        }

        if (!NewWildCard && ExistingWildCard) {
            break; // End of specific address matches. Done searching.
        }

        if (NewWildCard != ExistingWildCard) {
            continue;
        }

        if (NewFamily != QUIC_ADDRESS_FAMILY_UNSPEC && !QuicAddrCompareIp(NewAddr, ExistingAddr)) {
            continue;
        }

        if (QuicListenerHasAlpnOverlap(NewListener, ExistingListener)) {
            QuicTraceLogWarning(
                BindingListenerAlreadyRegistered,
                "[bind][%p] Listener (%p) already registered on ALPN",
                Binding, ExistingListener);
            AddNewListener = FALSE;
            break;
        }
    }

    if (AddNewListener) {
        MaximizeLookup = CxPlatListIsEmpty(&Binding->Listeners);

        //
        // If we search all the way back to the head of the list, just insert
        // the new listener at the end of the list. Otherwise, we terminated
        // prematurely based on sort order. Insert the new listener right before
        // the current Link.
        //
        if (Link == &Binding->Listeners) {
            CxPlatListInsertTail(&Binding->Listeners, &NewListener->Link);
        } else {
            NewListener->Link.Flink = Link;
            NewListener->Link.Blink = Link->Blink;
            NewListener->Link.Blink->Flink = &NewListener->Link;
            Link->Blink = &NewListener->Link;
        }
    }

    CxPlatDispatchRwLockReleaseExclusive(&Binding->RwLock);

    if (MaximizeLookup &&
        !QuicLookupMaximizePartitioning(&Binding->Lookup)) {
        QuicBindingUnregisterListener(Binding, NewListener);
        AddNewListener = FALSE;
    }

    return AddNewListener;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != NULL)
QUIC_LISTENER*
QuicBindingGetListener(
    _In_ QUIC_BINDING* Binding,
    _In_opt_ QUIC_CONNECTION* Connection,
    _Inout_ QUIC_NEW_CONNECTION_INFO* Info
    )
{
    UNREFERENCED_PARAMETER(Connection);
    QUIC_LISTENER* Listener = NULL;

    const QUIC_ADDR* Addr = Info->LocalAddress;
    const QUIC_ADDRESS_FAMILY Family = QuicAddrGetFamily(Addr);

    BOOLEAN FailedAlpnMatch = FALSE;
    BOOLEAN FailedAddrMatch = TRUE;

    CxPlatDispatchRwLockAcquireShared(&Binding->RwLock);

    for (CXPLAT_LIST_ENTRY* Link = Binding->Listeners.Flink;
        Link != &Binding->Listeners;
        Link = Link->Flink) {

        QUIC_LISTENER* ExistingListener =
            CXPLAT_CONTAINING_RECORD(Link, QUIC_LISTENER, Link);
        const QUIC_ADDR* ExistingAddr = &ExistingListener->LocalAddress;
        const BOOLEAN ExistingWildCard = ExistingListener->WildCard;
        const QUIC_ADDRESS_FAMILY ExistingFamily = QuicAddrGetFamily(ExistingAddr);
        FailedAlpnMatch = FALSE;

        if (ExistingFamily != QUIC_ADDRESS_FAMILY_UNSPEC) {
            if (Family != ExistingFamily ||
                (!ExistingWildCard && !QuicAddrCompareIp(Addr, ExistingAddr))) {
                FailedAddrMatch = TRUE;
                continue; // No IP match.
            }
        }
        FailedAddrMatch = FALSE;

        if (QuicListenerMatchesAlpn(ExistingListener, Info)) {
            if (CxPlatRefIncrementNonZero(&ExistingListener->RefCount, 1)) {
                Listener = ExistingListener;
            }
            goto Done;
        } else {
            FailedAlpnMatch = TRUE;
        }
    }

Done:

    CxPlatDispatchRwLockReleaseShared(&Binding->RwLock);

    if (FailedAddrMatch) {
        QuicTraceEvent(
            ConnNoListenerIp,
            "[conn][%p] No Listener for IP address: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(*Addr), Addr));
    } else if (FailedAlpnMatch) {
        QuicTraceEvent(
            ConnNoListenerAlpn,
            "[conn][%p] No listener matching ALPN: %!ALPN!",
            Connection,
            CASTED_CLOG_BYTEARRAY(Info->ClientAlpnListLength, Info->ClientAlpnList));
        QuicPerfCounterIncrement(QUIC_PERF_COUNTER_CONN_NO_ALPN);
    }

    return Listener;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicBindingUnregisterListener(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_LISTENER* Listener
    )
{
    CxPlatDispatchRwLockAcquireExclusive(&Binding->RwLock);
    CxPlatListEntryRemove(&Listener->Link);
    CxPlatDispatchRwLockReleaseExclusive(&Binding->RwLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicBindingAcceptConnection(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_NEW_CONNECTION_INFO* Info
    )
{
    //
    // Find a listener that matches the incoming connection request, by IP, port
    // and ALPN.
    //
    QUIC_LISTENER* Listener = QuicBindingGetListener(Binding, Connection, Info);
    if (Listener == NULL) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "No listener found for connection");
        QuicConnTransportError(
            Connection,
            QUIC_ERROR_CRYPTO_NO_APPLICATION_PROTOCOL);
        return;
    }

    //
    // Save the negotiated ALPN (starting with the length prefix) to be
    // used later in building up the TLS response.
    //
    uint16_t NegotiatedAlpnLength = 1 + Info->NegotiatedAlpn[-1];
    uint8_t* NegotiatedAlpn;

    if (NegotiatedAlpnLength <= TLS_SMALL_ALPN_BUFFER_SIZE) {
        NegotiatedAlpn = Connection->Crypto.TlsState.SmallAlpnBuffer;
    } else {
        NegotiatedAlpn = CXPLAT_ALLOC_NONPAGED(NegotiatedAlpnLength, QUIC_POOL_ALPN);
        if (NegotiatedAlpn == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "NegotiatedAlpn",
                NegotiatedAlpnLength);
            QuicConnTransportError(
                Connection,
                QUIC_ERROR_INTERNAL_ERROR);
            goto Error;
        }
    }
    CxPlatCopyMemory(NegotiatedAlpn, Info->NegotiatedAlpn - 1, NegotiatedAlpnLength);
    Connection->Crypto.TlsState.NegotiatedAlpn = NegotiatedAlpn;

    //
    // Allow for the listener to decide if it wishes to accept the incoming
    // connection.
    //
    QuicListenerAcceptConnection(Listener, Connection, Info);

Error:

    QuicListenerRelease(Listener, TRUE);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicBindingAddSourceConnectionID(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_CID_HASH_ENTRY* SourceCid
    )
{
    return QuicLookupAddLocalCid(&Binding->Lookup, SourceCid, NULL);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingRemoveSourceConnectionID(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_CID_HASH_ENTRY* SourceCid,
    _In_ CXPLAT_SLIST_ENTRY** Entry
    )
{
    QuicLookupRemoveLocalCid(&Binding->Lookup, SourceCid, Entry);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingRemoveConnection(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_CONNECTION* Connection
    )
{
    if (Connection->RemoteHashEntry != NULL) {
        QuicLookupRemoveRemoteHash(&Binding->Lookup, Connection->RemoteHashEntry);
    }
    QuicLookupRemoveLocalCids(&Binding->Lookup, Connection);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingMoveSourceConnectionIDs(
    _In_ QUIC_BINDING* BindingSrc,
    _In_ QUIC_BINDING* BindingDest,
    _In_ QUIC_CONNECTION* Connection
    )
{
    QuicLookupMoveLocalConnectionIDs(
        &BindingSrc->Lookup, &BindingDest->Lookup, Connection);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingOnConnectionHandshakeConfirmed(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_CONNECTION* Connection
    )
{
    if (Connection->RemoteHashEntry != NULL) {
        QuicLookupRemoveRemoteHash(&Binding->Lookup, Connection->RemoteHashEntry);
    }
}

//
// This attempts to add a new stateless operation (for a given remote endpoint)
// to the tracking structures in the binding. It first ages out any old
// operations that might have expired. Then it adds the new operation only if
// the remote address isn't already in the table.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATELESS_CONTEXT*
QuicBindingCreateStatelessOperation(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_WORKER* Worker,
    _In_ CXPLAT_RECV_DATA* Datagram
    )
{
    uint32_t TimeMs = CxPlatTimeMs32();
    const QUIC_ADDR* RemoteAddress = &Datagram->Route->RemoteAddress;
    uint32_t Hash = QuicAddrHash(RemoteAddress);
    QUIC_STATELESS_CONTEXT* StatelessCtx = NULL;

    CxPlatDispatchLockAcquire(&Binding->StatelessOperLock);

    if (Binding->RefCount == 0) {
        goto Exit;
    }

    //
    // Age out all expired operation contexts.
    //
    while (!CxPlatListIsEmpty(&Binding->StatelessOperList)) {
        QUIC_STATELESS_CONTEXT* OldStatelessCtx =
            CXPLAT_CONTAINING_RECORD(
                Binding->StatelessOperList.Flink,
                QUIC_STATELESS_CONTEXT,
                ListEntry);

        if (CxPlatTimeDiff32(OldStatelessCtx->CreationTimeMs, TimeMs) <
            (uint32_t)MsQuicLib.Settings.StatelessOperationExpirationMs) {
            break;
        }

        //
        // The operation is expired. Remove it from the tracking structures.
        //
        OldStatelessCtx->IsExpired = TRUE;
        CxPlatHashtableRemove(
            &Binding->StatelessOperTable,
            &OldStatelessCtx->TableEntry,
            NULL);
        CxPlatListEntryRemove(&OldStatelessCtx->ListEntry);
        Binding->StatelessOperCount--;

        //
        // If it's also processed, free it.
        //
        if (OldStatelessCtx->IsProcessed) {
            CxPlatPoolFree(
                &OldStatelessCtx->Worker->StatelessContextPool,
                OldStatelessCtx);
        }
    }

    if (Binding->StatelessOperCount >= (uint32_t)MsQuicLib.Settings.MaxBindingStatelessOperations) {
        QuicPacketLogDrop(Binding, CxPlatDataPathRecvDataToRecvPacket(Datagram),
            "Max binding operations reached");
        goto Exit;
    }

    //
    // Check for pre-existing operations already in the tracking structures.
    //

    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CXPLAT_HASHTABLE_ENTRY* TableEntry =
        CxPlatHashtableLookup(&Binding->StatelessOperTable, Hash, &Context);

    while (TableEntry != NULL) {
        const QUIC_STATELESS_CONTEXT* ExistingCtx =
            CXPLAT_CONTAINING_RECORD(TableEntry, QUIC_STATELESS_CONTEXT, TableEntry);

        if (QuicAddrCompare(&ExistingCtx->RemoteAddress, RemoteAddress)) {
            QuicPacketLogDrop(Binding, CxPlatDataPathRecvDataToRecvPacket(Datagram),
                "Already in stateless oper table");
            goto Exit;
        }

        TableEntry =
            CxPlatHashtableLookupNext(&Binding->StatelessOperTable, &Context);
    }

    //
    // Not already in the tracking structures, so allocate and insert a new one.
    //

    StatelessCtx =
        (QUIC_STATELESS_CONTEXT*)CxPlatPoolAlloc(&Worker->StatelessContextPool);
    if (StatelessCtx == NULL) {
        QuicPacketLogDrop(Binding, CxPlatDataPathRecvDataToRecvPacket(Datagram),
            "Alloc failure for stateless oper ctx");
        goto Exit;
    }

    StatelessCtx->Binding = Binding;
    StatelessCtx->Worker = Worker;
    StatelessCtx->Datagram = Datagram;
    StatelessCtx->CreationTimeMs = TimeMs;
    StatelessCtx->HasBindingRef = FALSE;
    StatelessCtx->IsProcessed = FALSE;
    StatelessCtx->IsExpired = FALSE;
    CxPlatCopyMemory(&StatelessCtx->RemoteAddress, RemoteAddress, sizeof(QUIC_ADDR));

    CxPlatHashtableInsert(
        &Binding->StatelessOperTable,
        &StatelessCtx->TableEntry,
        Hash,
        NULL); // TODO - Context?

    CxPlatListInsertTail(
        &Binding->StatelessOperList,
        &StatelessCtx->ListEntry
        );

    Binding->StatelessOperCount++;

Exit:

    CxPlatDispatchLockRelease(&Binding->StatelessOperLock);

    return StatelessCtx;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicBindingQueueStatelessOperation(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_OPERATION_TYPE OperType,
    _In_ CXPLAT_RECV_DATA* Datagram
    )
{
    if (MsQuicLib.StatelessRegistration == NULL) {
        QuicPacketLogDrop(Binding, CxPlatDataPathRecvDataToRecvPacket(Datagram),
            "NULL stateless registration");
        return FALSE;
    }

    QUIC_WORKER* Worker = QuicLibraryGetWorker(Datagram);
    if (QuicWorkerIsOverloaded(Worker)) {
        QuicPacketLogDrop(Binding, CxPlatDataPathRecvDataToRecvPacket(Datagram),
            "Stateless worker overloaded (stateless oper)");
        return FALSE;
    }

    QUIC_STATELESS_CONTEXT* Context =
        QuicBindingCreateStatelessOperation(Binding, Worker, Datagram);
    if (Context == NULL) {
        return FALSE;
    }

    QUIC_OPERATION* Oper = QuicOperationAlloc(Worker, OperType);
    if (Oper == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "stateless operation",
            sizeof(QUIC_OPERATION));
        QuicPacketLogDrop(
            Binding,
            CxPlatDataPathRecvDataToRecvPacket(Datagram),
            "Alloc failure for stateless operation");
        QuicBindingReleaseStatelessOperation(Context, FALSE);
        return FALSE;
    }

    Oper->STATELESS.Context = Context;
    QuicWorkerQueueOperation(Worker, Oper);

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicBindingProcessStatelessOperation(
    _In_ uint32_t OperationType,
    _In_ QUIC_STATELESS_CONTEXT* StatelessCtx
    )
{
    QUIC_BINDING* Binding = StatelessCtx->Binding;
    CXPLAT_RECV_DATA* RecvDatagram = StatelessCtx->Datagram;
    CXPLAT_RECV_PACKET* RecvPacket =
        CxPlatDataPathRecvDataToRecvPacket(RecvDatagram);
    QUIC_BUFFER* SendDatagram = NULL;

    CXPLAT_DBG_ASSERT(RecvPacket->ValidatedHeaderInv);

    QuicTraceEvent(
        BindingExecOper,
        "[bind][%p] Execute: %u",
        Binding,
        OperationType);

    CXPLAT_SEND_DATA* SendData =
        CxPlatSendDataAlloc(
            Binding->Socket,
            CXPLAT_ECN_NON_ECT,
            0,
            RecvDatagram->Route);
    if (SendData == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "stateless send data",
            0);
        goto Exit;
    }

    if (OperationType == QUIC_OPER_TYPE_VERSION_NEGOTIATION) {

        CXPLAT_DBG_ASSERT(RecvPacket->DestCid != NULL);
        CXPLAT_DBG_ASSERT(RecvPacket->SourceCid != NULL);

        const uint32_t* SupportedVersions;
        uint32_t SupportedVersionsLength;
        if (MsQuicLib.Settings.IsSet.VersionSettings) {
            SupportedVersions = MsQuicLib.Settings.VersionSettings->OfferedVersions;
            SupportedVersionsLength = MsQuicLib.Settings.VersionSettings->OfferedVersionsLength;
        } else {
            SupportedVersions = DefaultSupportedVersionsList;
            SupportedVersionsLength = ARRAYSIZE(DefaultSupportedVersionsList);
        }

        const uint16_t PacketLength =
            sizeof(QUIC_VERSION_NEGOTIATION_PACKET) +               // Header
            RecvPacket->SourceCidLen +
            sizeof(uint8_t) +
            RecvPacket->DestCidLen +
            sizeof(uint32_t) +                                      // One random version
            (uint16_t)(SupportedVersionsLength * sizeof(uint32_t)); // Our actual supported versions

        SendDatagram =
            CxPlatSendDataAllocBuffer(SendData, PacketLength);
        if (SendDatagram == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "vn datagram",
                PacketLength);
            goto Exit;
        }

        QUIC_VERSION_NEGOTIATION_PACKET* VerNeg =
            (QUIC_VERSION_NEGOTIATION_PACKET*)SendDatagram->Buffer;
        CXPLAT_DBG_ASSERT(SendDatagram->Length == PacketLength);

        VerNeg->IsLongHeader = TRUE;
        VerNeg->Version = QUIC_VERSION_VER_NEG;

        uint8_t* Buffer = VerNeg->DestCid;
        VerNeg->DestCidLength = RecvPacket->SourceCidLen;
        CxPlatCopyMemory(
            Buffer,
            RecvPacket->SourceCid,
            RecvPacket->SourceCidLen);
        Buffer += RecvPacket->SourceCidLen;

        *Buffer = RecvPacket->DestCidLen;
        Buffer++;
        CxPlatCopyMemory(
            Buffer,
            RecvPacket->DestCid,
            RecvPacket->DestCidLen);
        Buffer += RecvPacket->DestCidLen;

        uint8_t RandomValue = 0;
        CxPlatRandom(sizeof(uint8_t), &RandomValue);
        VerNeg->Unused = 0x7F & RandomValue;

        CxPlatCopyMemory(Buffer, &Binding->RandomReservedVersion, sizeof(uint32_t));
        Buffer += sizeof(uint32_t);

        CxPlatCopyMemory(
            Buffer,
            SupportedVersions,
            SupportedVersionsLength * sizeof(uint32_t));

        CXPLAT_RECV_PACKET* Packet = CxPlatDataPathRecvDataToRecvPacket(RecvDatagram);
        Packet->ReleaseDeferred = FALSE;

        QuicTraceLogVerbose(
            PacketTxVersionNegotiation,
            "[S][TX][-] VN");

    } else if (OperationType == QUIC_OPER_TYPE_STATELESS_RESET) {

        CXPLAT_DBG_ASSERT(RecvPacket->DestCid != NULL);
        CXPLAT_DBG_ASSERT(RecvPacket->SourceCid == NULL);

        //
        // There are a few requirements for sending stateless reset packets:
        //
        //   - It must be smaller than the received packet.
        //   - It must be larger than a spec defined minimum (39 bytes).
        //   - It must be sufficiently random so that a middle box cannot easily
        //     detect that it is a stateless reset packet.
        //

        //
        // Add a bit of randomness (3 bits worth) to the packet length.
        //
        uint8_t PacketLength;
        CxPlatRandom(sizeof(PacketLength), &PacketLength);
        PacketLength >>= 5; // Only drop 5 of the 8 bits of randomness.
        PacketLength += QUIC_RECOMMENDED_STATELESS_RESET_PACKET_LENGTH;

        if (PacketLength >= RecvPacket->BufferLength) {
            //
            // Can't go over the recieve packet's length.
            //
            PacketLength = (uint8_t)RecvPacket->BufferLength - 1;
        }

        if (PacketLength < QUIC_MIN_STATELESS_RESET_PACKET_LENGTH) {
            CXPLAT_DBG_ASSERT(FALSE);
            goto Exit;
        }

        SendDatagram =
            CxPlatSendDataAllocBuffer(SendData, PacketLength);
        if (SendDatagram == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "reset datagram",
                PacketLength);
            goto Exit;
        }

        QUIC_SHORT_HEADER_V1* ResetPacket =
            (QUIC_SHORT_HEADER_V1*)SendDatagram->Buffer;
        CXPLAT_DBG_ASSERT(SendDatagram->Length == PacketLength);

        CxPlatRandom(
            PacketLength - QUIC_STATELESS_RESET_TOKEN_LENGTH,
            SendDatagram->Buffer);
        ResetPacket->IsLongHeader = FALSE;
        ResetPacket->FixedBit = 1;
        ResetPacket->KeyPhase = RecvPacket->SH->KeyPhase;
        QuicLibraryGenerateStatelessResetToken(
            RecvPacket->DestCid,
            SendDatagram->Buffer + PacketLength - QUIC_STATELESS_RESET_TOKEN_LENGTH);

        QuicTraceLogVerbose(
            PacketTxStatelessReset,
            "[S][TX][-] SR %s",
            QuicCidBufToStr(
                SendDatagram->Buffer + PacketLength - QUIC_STATELESS_RESET_TOKEN_LENGTH,
                QUIC_STATELESS_RESET_TOKEN_LENGTH
            ).Buffer);

        QuicPerfCounterIncrement(QUIC_PERF_COUNTER_SEND_STATELESS_RESET);

    } else if (OperationType == QUIC_OPER_TYPE_RETRY) {

        CXPLAT_DBG_ASSERT(RecvPacket->DestCid != NULL);
        CXPLAT_DBG_ASSERT(RecvPacket->SourceCid != NULL);

        uint16_t PacketLength = QuicPacketMaxBufferSizeForRetryV1();
        SendDatagram =
            CxPlatSendDataAllocBuffer(SendData, PacketLength);
        if (SendDatagram == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "retry datagram",
                PacketLength);
            goto Exit;
        }

        uint8_t NewDestCid[QUIC_CID_MAX_LENGTH];
        CXPLAT_DBG_ASSERT(sizeof(NewDestCid) >= MsQuicLib.CidTotalLength);
        CxPlatRandom(sizeof(NewDestCid), NewDestCid);

        QUIC_TOKEN_CONTENTS Token = { 0 };
        Token.Authenticated.Timestamp = (uint64_t)CxPlatTimeEpochMs64();
        Token.Authenticated.IsNewToken = FALSE;

        Token.Encrypted.RemoteAddress = RecvDatagram->Route->RemoteAddress;
        CxPlatCopyMemory(Token.Encrypted.OrigConnId, RecvPacket->DestCid, RecvPacket->DestCidLen);
        Token.Encrypted.OrigConnIdLength = RecvPacket->DestCidLen;

        uint8_t Iv[CXPLAT_MAX_IV_LENGTH];
        if (MsQuicLib.CidTotalLength >= CXPLAT_IV_LENGTH) {
            CxPlatCopyMemory(Iv, NewDestCid, CXPLAT_IV_LENGTH);
            for (uint8_t i = CXPLAT_IV_LENGTH; i < MsQuicLib.CidTotalLength; ++i) {
                Iv[i % CXPLAT_IV_LENGTH] ^= NewDestCid[i];
            }
        } else {
            CxPlatZeroMemory(Iv, CXPLAT_IV_LENGTH);
            CxPlatCopyMemory(Iv, NewDestCid, MsQuicLib.CidTotalLength);
        }

        CxPlatDispatchLockAcquire(&MsQuicLib.StatelessRetryKeysLock);

        CXPLAT_KEY* StatelessRetryKey = QuicLibraryGetCurrentStatelessRetryKey();
        if (StatelessRetryKey == NULL) {
            CxPlatDispatchLockRelease(&MsQuicLib.StatelessRetryKeysLock);
            goto Exit;
        }

        QUIC_STATUS Status =
            CxPlatEncrypt(
                StatelessRetryKey,
                Iv,
                sizeof(Token.Authenticated), (uint8_t*) &Token.Authenticated,
                sizeof(Token.Encrypted) + sizeof(Token.EncryptionTag), (uint8_t*)&(Token.Encrypted));

        CxPlatDispatchLockRelease(&MsQuicLib.StatelessRetryKeysLock);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }

        SendDatagram->Length =
            QuicPacketEncodeRetryV1(
                RecvPacket->LH->Version,
                RecvPacket->SourceCid, RecvPacket->SourceCidLen,
                NewDestCid, MsQuicLib.CidTotalLength,
                RecvPacket->DestCid, RecvPacket->DestCidLen,
                sizeof(Token),
                (uint8_t*)&Token,
                (uint16_t)SendDatagram->Length,
                SendDatagram->Buffer);
        if (SendDatagram->Length == 0) {
            CXPLAT_DBG_ASSERT(CxPlatIsRandomMemoryFailureEnabled());
            goto Exit;
        }

        QuicTraceLogVerbose(
            PacketTxRetry,
            "[S][TX][-] LH Ver:0x%x DestCid:%s SrcCid:%s Type:R OrigDestCid:%s (Token %hu bytes)",
            RecvPacket->LH->Version,
            QuicCidBufToStr(RecvPacket->SourceCid, RecvPacket->SourceCidLen).Buffer,
            QuicCidBufToStr(NewDestCid, MsQuicLib.CidTotalLength).Buffer,
            QuicCidBufToStr(RecvPacket->DestCid, RecvPacket->DestCidLen).Buffer,
            (uint16_t)sizeof(Token));

        QuicPerfCounterIncrement(QUIC_PERF_COUNTER_SEND_STATELESS_RETRY);

    } else {
        CXPLAT_TEL_ASSERT(FALSE); // Should be unreachable code.
        goto Exit;
    }

    QuicBindingSend(
        Binding,
        RecvDatagram->Route,
        SendData,
        SendDatagram->Length,
        1,
        RecvDatagram->PartitionIndex % MsQuicLib.PartitionCount);
    SendData = NULL;

Exit:

    if (SendData != NULL) {
        CxPlatSendDataFree(SendData);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicBindingReleaseStatelessOperation(
    _In_ QUIC_STATELESS_CONTEXT* StatelessCtx,
    _In_ BOOLEAN ReturnDatagram
    )
{
    QUIC_BINDING* Binding = StatelessCtx->Binding;

    if (ReturnDatagram) {
        CxPlatRecvDataReturn(StatelessCtx->Datagram);
    }
    StatelessCtx->Datagram = NULL;

    CxPlatDispatchLockAcquire(&Binding->StatelessOperLock);

    StatelessCtx->IsProcessed = TRUE;
    uint8_t FreeCtx = StatelessCtx->IsExpired;

    CxPlatDispatchLockRelease(&Binding->StatelessOperLock);

    if (StatelessCtx->HasBindingRef) {
        QuicLibraryReleaseBinding(Binding);
    }

    if (FreeCtx) {
        CxPlatPoolFree(
            &StatelessCtx->Worker->StatelessContextPool,
            StatelessCtx);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicBindingQueueStatelessReset(
    _In_ QUIC_BINDING* Binding,
    _In_ CXPLAT_RECV_DATA* Datagram
    )
{
    CXPLAT_DBG_ASSERT(!Binding->Exclusive);
    CXPLAT_DBG_ASSERT(!((QUIC_SHORT_HEADER_V1*)Datagram->Buffer)->IsLongHeader);

    if (Datagram->BufferLength <= QUIC_MIN_STATELESS_RESET_PACKET_LENGTH) {
        QuicPacketLogDrop(Binding, CxPlatDataPathRecvDataToRecvPacket(Datagram),
            "Packet too short for stateless reset");
        return FALSE;
    }

    if (Binding->Exclusive) {
        //
        // Can't support stateless reset in exclusive mode, because we don't use
        // a connection ID. Without a connection ID, a stateless reset token
        // cannot be generated.
        //
        QuicPacketLogDrop(Binding, CxPlatDataPathRecvDataToRecvPacket(Datagram),
            "No stateless reset on exclusive binding");
        return FALSE;
    }

    return
        QuicBindingQueueStatelessOperation(
            Binding, QUIC_OPER_TYPE_STATELESS_RESET, Datagram);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicBindingPreprocessDatagram(
    _In_ QUIC_BINDING* Binding,
    _Inout_ CXPLAT_RECV_DATA* Datagram,
    _Out_ BOOLEAN* ReleaseDatagram
    )
{
    CXPLAT_RECV_PACKET* Packet = CxPlatDataPathRecvDataToRecvPacket(Datagram);
    CxPlatZeroMemory(&Packet->PacketNumber, sizeof(CXPLAT_RECV_PACKET) - sizeof(uint64_t));
    Packet->Buffer = Datagram->Buffer;
    Packet->BufferLength = Datagram->BufferLength;

    *ReleaseDatagram = TRUE;

    //
    // Get the destination connection ID from the packet so we can use it for
    // determining delivery partition. All this must be version INDEPENDENT as
    // we haven't done any version validation at this point.
    //

    if (!QuicPacketValidateInvariant(Binding, Packet, !Binding->Exclusive)) {
        return FALSE;
    }

    if (Packet->Invariant->IsLongHeader) {
        //
        // Validate we support this long header packet version.
        //
        if (Packet->Invariant->LONG_HDR.Version != QUIC_VERSION_VER_NEG &&
            !QuicVersionNegotiationExtIsVersionServerSupported(Packet->Invariant->LONG_HDR.Version)) {
            //
            // The QUIC packet has an unsupported and non-VN packet number. If
            // we have a listener on this binding and the packet is long enough
            // we should respond with a version negotiation packet.
            //
            if (!QuicBindingHasListenerRegistered(Binding)) {
                QuicPacketLogDrop(Binding, Packet, "No listener to send VN");

            } else if (Datagram->BufferLength < QUIC_MIN_UDP_PAYLOAD_LENGTH_FOR_VN) {
                QuicPacketLogDrop(Binding, Packet, "Too small to send VN");

            } else {
                *ReleaseDatagram =
                    !QuicBindingQueueStatelessOperation(
                        Binding, QUIC_OPER_TYPE_VERSION_NEGOTIATION, Datagram);
            }
            return FALSE;
        }

        if (Binding->Exclusive) {
            if (Packet->DestCidLen != 0) {
                QuicPacketLogDrop(Binding, Packet, "Non-zero length CID on exclusive binding");
                return FALSE;
            }
        } else {
            if (Packet->DestCidLen == 0) {
                QuicPacketLogDrop(Binding, Packet, "Zero length DestCid");
                return FALSE;
            }
            if (Packet->DestCidLen < QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH) {
                QuicPacketLogDrop(Binding, Packet, "Less than min length CID on non-exclusive binding");
                return FALSE;
            }
        }
    }

    *ReleaseDatagram = FALSE;

    return TRUE;
}

//
// Returns TRUE if we should respond to the connection attempt with a Retry
// packet.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicBindingShouldRetryConnection(
    _In_ const QUIC_BINDING* const Binding,
    _In_ CXPLAT_RECV_PACKET* Packet,
    _In_ uint16_t TokenLength,
    _In_reads_(TokenLength)
        const uint8_t* Token,
    _Inout_ BOOLEAN* DropPacket
    )
{
    //
    // This is only called once we've determined we can create a new connection.
    // If there is a token, it validates the token. If there is no token, then
    // the function checks to see if the binding currently has too many
    // connections in the handshake state already. If so, it requests the client
    // to retry its connection attempt to prove source address ownership.
    //

    if (TokenLength != 0) {
        //
        // Must always validate the token when provided by the client. Failure
        // to validate retry tokens is fatal. Failure to validate NEW_TOKEN
        // tokens is not.
        //
        if (QuicPacketValidateInitialToken(
                Binding, Packet, TokenLength, Token, DropPacket)) {
            Packet->ValidToken = TRUE;
            return FALSE;
        }
        if (*DropPacket) {
            return FALSE;
        }
    }

    uint64_t CurrentMemoryLimit =
        (MsQuicLib.Settings.RetryMemoryLimit * CxPlatTotalMemory) / UINT16_MAX;

    return MsQuicLib.CurrentHandshakeMemoryUsage >= CurrentMemoryLimit;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_CONNECTION*
QuicBindingCreateConnection(
    _In_ QUIC_BINDING* Binding,
    _In_ const CXPLAT_RECV_DATA* const Datagram
    )
{
    //
    // This function returns either a new connection, or an existing
    // connection if a collision is discovered on calling
    // QuicLookupAddRemoteHash.
    //

    CXPLAT_RECV_PACKET* Packet = CxPlatDataPathRecvDataToRecvPacket(Datagram);

    //
    // Pick a stateless worker to process the client hello and if successful,
    // the connection will later be moved to the correct registration's worker.
    //
    QUIC_WORKER* Worker = QuicLibraryGetWorker(Datagram);
    if (QuicWorkerIsOverloaded(Worker)) {
        QuicPacketLogDrop(Binding, Packet, "Stateless worker overloaded");
        return NULL;
    }

    QUIC_CONNECTION* Connection = NULL;
    QUIC_CONNECTION* NewConnection;
    QUIC_STATUS Status =
        QuicConnAlloc(
            MsQuicLib.StatelessRegistration,
            Datagram,
            &NewConnection);
    if (QUIC_FAILED(Status)) {
        QuicPacketLogDrop(Binding, Packet, "Failed to initialize new connection");
        return NULL;
    }

    QuicWorkerAssignConnection(Worker, NewConnection);

    BOOLEAN BindingRefAdded = FALSE;
    CXPLAT_DBG_ASSERT(NewConnection->SourceCids.Next != NULL);
    QUIC_CID_HASH_ENTRY* SourceCid =
        CXPLAT_CONTAINING_RECORD(
            NewConnection->SourceCids.Next,
            QUIC_CID_HASH_ENTRY,
            Link);

    QuicConnAddRef(NewConnection, QUIC_CONN_REF_LOOKUP_RESULT);

    //
    // Even though the new connection might not end up being put in this
    // binding's lookup table, it must be completely set up before it is
    // inserted into the table. Once in the table, other threads/processors
    // could immediately be queuing new operations.
    //

    if (!QuicLibraryTryAddRefBinding(Binding)) {
        QuicPacketLogDrop(Binding, CxPlatDataPathRecvDataToRecvPacket(Datagram),
            "Clean up in progress");
        goto Exit;
    }

    BindingRefAdded = TRUE;
    NewConnection->Paths[0].Binding = Binding;

    if (!QuicLookupAddRemoteHash(
            &Binding->Lookup,
            NewConnection,
            &Datagram->Route->RemoteAddress,
            Packet->SourceCidLen,
            Packet->SourceCid,
            &Connection)) {
        //
        // Collision with an existing connection or a memory failure.
        //
        if (Connection == NULL) {
            QuicPacketLogDrop(Binding, Packet, "Failed to insert remote hash");
        }
        goto Exit;
    }

    QuicWorkerQueueConnection(NewConnection->Worker, NewConnection);

    return NewConnection;

Exit:

    if (BindingRefAdded) {
        QuicConnRelease(NewConnection, QUIC_CONN_REF_LOOKUP_RESULT);
        //
        // The binding ref cannot be released on the receive thread. So, once
        // it has been acquired, we must queue the connection, only to shut it
        // down.
        //
#pragma warning(push)
#pragma prefast(suppress:6001, "SAL doesn't understand ref counts")
        if (InterlockedCompareExchange16(
                (short*)&NewConnection->BackUpOperUsed, 1, 0) == 0) {
            QUIC_OPERATION* Oper = &NewConnection->BackUpOper;
            Oper->FreeAfterProcess = FALSE;
            Oper->Type = QUIC_OPER_TYPE_API_CALL;
            Oper->API_CALL.Context = &NewConnection->BackupApiContext;
            Oper->API_CALL.Context->Type = QUIC_API_TYPE_CONN_SHUTDOWN;
            Oper->API_CALL.Context->CONN_SHUTDOWN.Flags = QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT;
            Oper->API_CALL.Context->CONN_SHUTDOWN.ErrorCode = 0;
            Oper->API_CALL.Context->CONN_SHUTDOWN.RegistrationShutdown = FALSE;
            QuicConnQueueOper(NewConnection, Oper);
        }
#pragma warning(pop)

    } else {
        NewConnection->SourceCids.Next = NULL;
        CXPLAT_FREE(SourceCid, QUIC_POOL_CIDHASH);
        QuicConnRelease(NewConnection, QUIC_CONN_REF_LOOKUP_RESULT);
#pragma prefast(suppress:6001, "SAL doesn't understand ref counts")
        QuicConnRelease(NewConnection, QUIC_CONN_REF_HANDLE_OWNER);
    }

    return Connection;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicBindingDropBlockedSourcePorts(
    _In_ QUIC_BINDING* Binding,
    _In_ const CXPLAT_RECV_DATA* const Datagram
    )
{
    const uint16_t SourcePort = QuicAddrGetPort(&Datagram->Route->RemoteAddress);

    //
    // These UDP source ports are recommended to be blocked by the QUIC WG. See
    // draft-ietf-quic-applicability for more details on the set of ports that
    // may cause issues.
    //
    // N.B - This list MUST be sorted in decreasing order.
    //
    const uint16_t BlockedPorts[] = {
        11211,  // memcache
        5353,   // mDNS
        1900,   // SSDP
        500,    // IKE
        389,    // CLDAP
        161,    // SNMP
        138,    // NETBIOS Datagram Service
        137,    // NETBIOS Name Service
        123,    // NTP
        111,    // Portmap
        53,     // DNS
        19,     // Chargen
        17,     // Quote of the Day
        0,      // Unusable
    };

    for (size_t i = 0; i < ARRAYSIZE(BlockedPorts) && SourcePort <= BlockedPorts[i]; ++i) {
        if (BlockedPorts[i] == SourcePort) {
            QuicPacketLogDrop(
                Binding,
                CxPlatDataPathRecvDataToRecvPacket(Datagram),
                "Blocked source port");
            return TRUE;
        }
    }

    return FALSE;
}

//
// Looks up or creates a connection to handle a chain of datagrams.
// Returns TRUE if the datagrams were delivered, and FALSE if they should be
// dropped.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
BOOLEAN
QuicBindingDeliverDatagrams(
    _In_ QUIC_BINDING* Binding,
    _In_ CXPLAT_RECV_DATA* DatagramChain,
    _In_ uint32_t DatagramChainLength
    )
{
    CXPLAT_RECV_PACKET* Packet =
            CxPlatDataPathRecvDataToRecvPacket(DatagramChain);
    CXPLAT_DBG_ASSERT(Packet->ValidatedHeaderInv);

    //
    // For client owned bindings (for which we always control the CID) or for
    // short header packets for server owned bindings, the packet's destination
    // connection ID (DestCid) is the key for looking up the corresponding
    // connection object. The DestCid encodes the partition ID (PID) that can
    // be used for partitioning the look up table.
    //
    // For long header packets for server owned bindings, the packet's DestCid
    // was not necessarily generated locally, so cannot be used for lookup.
    // Instead, a hash of the remote address/port and source CID is used.
    //
    // If the lookup fails, and if there is a listener on the local 2-Tuple,
    // then a new connection is created and inserted into the binding's lookup
    // table.
    //
    // If a new connection is created, it will then be initially processed by
    // a library worker thread to decode the ALPN and SNI. That information
    // will then be used to find the associated listener. If not found, the
    // connection will be thrown away. Otherwise, the listener will then be
    // invoked to allow it to accept the connection and choose a server
    // certificate.
    //
    // If all else fails, and no connection was found or created for the
    // packet, then the packet is dropped.
    //

    QUIC_CONNECTION* Connection;
    if (!Binding->ServerOwned || Packet->IsShortHeader) {
        Connection =
            QuicLookupFindConnectionByLocalCid(
                &Binding->Lookup,
                Packet->DestCid,
                Packet->DestCidLen);
    } else {
        Connection =
            QuicLookupFindConnectionByRemoteHash(
                &Binding->Lookup,
                &DatagramChain->Route->RemoteAddress,
                Packet->SourceCidLen,
                Packet->SourceCid);
    }

    if (Connection == NULL) {

        //
        // Because the packet chain is ordered by control packets first, we
        // don't have to worry about a packet that can't create the connection
        // being in front of a packet that can in the chain. So we can always
        // use the head of the chain to determine if a new connection should
        // be created.
        //

        if (!Binding->ServerOwned) {
            QuicPacketLogDrop(Binding, Packet, "No matching client connection");
            return FALSE;
        }

        if (Binding->Exclusive) {
            QuicPacketLogDrop(Binding, Packet, "No connection on exclusive binding");
            return FALSE;
        }

        if (QuicBindingDropBlockedSourcePorts(Binding, DatagramChain)) {
            return FALSE;
        }

        if (Packet->IsShortHeader) {
            //
            // For unattributed short header packets we can try to send a
            // stateless reset back in response.
            //
            return QuicBindingQueueStatelessReset(Binding, DatagramChain);
        }

        if (Packet->Invariant->LONG_HDR.Version == QUIC_VERSION_VER_NEG) {
            QuicPacketLogDrop(Binding, Packet, "Version negotiation packet not matched with a connection");
            return FALSE;
        }

        //
        // The following logic is server specific for creating/accepting new
        // connections.
        //

        CXPLAT_DBG_ASSERT(QuicIsVersionSupported(Packet->Invariant->LONG_HDR.Version));

        //
        // Only Initial (version specific) packets are processed from here on.
        //
        switch (Packet->Invariant->LONG_HDR.Version) {
        case QUIC_VERSION_1:
        case QUIC_VERSION_DRAFT_29:
        case QUIC_VERSION_MS_1:
            if (Packet->LH->Type != QUIC_INITIAL_V1) {
                QuicPacketLogDrop(Binding, Packet, "Non-initial packet not matched with a connection");
                return FALSE;
            }
            break;
        case QUIC_VERSION_2:
            if (Packet->LH->Type != QUIC_INITIAL_V2) {
                QuicPacketLogDrop(Binding, Packet, "Non-initial packet not matched with a connection");
                return FALSE;
            }
        }

        const uint8_t* Token = NULL;
        uint16_t TokenLength = 0;
        if (!QuicPacketValidateLongHeaderV1(
                Binding,
                TRUE,
                Packet,
                &Token,
                &TokenLength)) {
            return FALSE;
        }

        CXPLAT_DBG_ASSERT(Token != NULL);

        if (!QuicBindingHasListenerRegistered(Binding)) {
            QuicPacketLogDrop(Binding, Packet, "No listeners registered to accept new connection.");
            return FALSE;
        }

        CXPLAT_DBG_ASSERT(Binding->ServerOwned);

        BOOLEAN DropPacket = FALSE;
        if (QuicBindingShouldRetryConnection(
                Binding, Packet, TokenLength, Token, &DropPacket)) {
            return
                QuicBindingQueueStatelessOperation(
                    Binding, QUIC_OPER_TYPE_RETRY, DatagramChain);
        }

        if (!DropPacket) {
            Connection = QuicBindingCreateConnection(Binding, DatagramChain);
        }
    }

    if (Connection == NULL) {
        return FALSE;
    }

    QuicConnQueueRecvDatagrams(Connection, DatagramChain, DatagramChainLength);
    QuicConnRelease(Connection, QUIC_CONN_REF_LOOKUP_RESULT);

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
void
QuicBindingReceive(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ void* RecvCallbackContext,
    _In_ CXPLAT_RECV_DATA* DatagramChain
    )
{
    UNREFERENCED_PARAMETER(Socket);
    CXPLAT_DBG_ASSERT(RecvCallbackContext != NULL);
    CXPLAT_DBG_ASSERT(DatagramChain != NULL);

    QUIC_BINDING* Binding = (QUIC_BINDING*)RecvCallbackContext;
    CXPLAT_RECV_DATA* ReleaseChain = NULL;
    CXPLAT_RECV_DATA** ReleaseChainTail = &ReleaseChain;
    CXPLAT_RECV_DATA* SubChain = NULL;
    CXPLAT_RECV_DATA** SubChainTail = &SubChain;
    CXPLAT_RECV_DATA** SubChainDataTail = &SubChain;
    uint32_t SubChainLength = 0;
    uint32_t TotalChainLength = 0;
    uint32_t TotalDatagramBytes = 0;

    //
    // Breaks the chain of datagrams into subchains by destination CID and
    // delivers the subchains.
    //
    // NB: All packets in a datagram are required to have the same destination
    // CID, so we don't split datagrams here. Later on, the packet handling
    // code will check that each packet has a destination CID matching the
    // connection it was delivered to.
    //

    uint32_t Proc = CxPlatProcCurrentNumber();
    uint64_t ProcShifted = ((uint64_t)Proc + 1) << 40;

    CXPLAT_RECV_DATA* Datagram;
    while ((Datagram = DatagramChain) != NULL) {
        TotalChainLength++;
        TotalDatagramBytes += Datagram->BufferLength;

        //
        // Remove the head.
        //
        DatagramChain = Datagram->Next;
        Datagram->Next = NULL;

        CXPLAT_RECV_PACKET* Packet =
            CxPlatDataPathRecvDataToRecvPacket(Datagram);
        CxPlatZeroMemory(Packet, sizeof(CXPLAT_RECV_PACKET));
        Packet->PacketId =
            ProcShifted | InterlockedIncrement64((int64_t*)&MsQuicLib.PerProc[Proc].ReceivePacketId);
        Packet->Buffer = Datagram->Buffer;
        Packet->BufferLength = Datagram->BufferLength;

        CXPLAT_DBG_ASSERT(Packet->PacketId != 0);
        QuicTraceEvent(
            PacketReceive,
            "[pack][%llu] Received",
            Packet->PacketId);

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
        //
        // The test datapath receive callback allows for test code to modify
        // the datagrams on the receive path, and optionally indicate one or
        // more to be dropped.
        //
        QUIC_TEST_DATAPATH_HOOKS* Hooks = MsQuicLib.TestDatapathHooks;
        if (Hooks != NULL) {
            if (Hooks->Receive(Datagram)) {
                *ReleaseChainTail = Datagram;
                ReleaseChainTail = &Datagram->Next;
                QuicPacketLogDrop(Binding, Packet, "Test Dropped");
                continue;
            }
        }
#endif

        //
        // Perform initial validation.
        //
        BOOLEAN ReleaseDatagram;
        if (!QuicBindingPreprocessDatagram(Binding, Datagram, &ReleaseDatagram)) {
            if (ReleaseDatagram) {
                *ReleaseChainTail = Datagram;
                ReleaseChainTail = &Datagram->Next;
            }
            continue;
        }

        CXPLAT_DBG_ASSERT(Packet->DestCid != NULL);
        CXPLAT_DBG_ASSERT(Packet->DestCidLen != 0 || Binding->Exclusive);
        CXPLAT_DBG_ASSERT(Packet->ValidatedHeaderInv);

        //
        // If the next datagram doesn't match the current subchain, deliver the
        // current subchain and start a new one.
        // (If the binding is exclusively owned, all datagrams are delivered to
        // the same connection and this chain-splitting step is skipped.)
        //
        CXPLAT_RECV_PACKET* SubChainPacket =
            SubChain == NULL ?
                NULL : CxPlatDataPathRecvDataToRecvPacket(SubChain);
        if (!Binding->Exclusive && SubChain != NULL &&
            (Packet->DestCidLen != SubChainPacket->DestCidLen ||
             memcmp(Packet->DestCid, SubChainPacket->DestCid, Packet->DestCidLen) != 0)) {
            if (!QuicBindingDeliverDatagrams(Binding, SubChain, SubChainLength)) {
                *ReleaseChainTail = SubChain;
                ReleaseChainTail = SubChainDataTail;
            }
            SubChain = NULL;
            SubChainTail = &SubChain;
            SubChainDataTail = &SubChain;
            SubChainLength = 0;
        }

        //
        // Insert the datagram into the current chain, with handshake packets
        // first (we assume handshake packets don't come after non-handshake
        // packets in a datagram).
        // We do this so that we can more easily determine if the chain of
        // packets can create a new connection.
        //

        SubChainLength++;
        if (!QuicPacketIsHandshake(Packet->Invariant)) {
            *SubChainDataTail = Datagram;
            SubChainDataTail = &Datagram->Next;
        } else {
            if (*SubChainTail == NULL) {
                *SubChainTail = Datagram;
                SubChainTail = &Datagram->Next;
                SubChainDataTail = &Datagram->Next;
            } else {
                Datagram->Next = *SubChainTail;
                *SubChainTail = Datagram;
                SubChainTail = &Datagram->Next;
            }
        }
    }

    if (SubChain != NULL) {
        //
        // Deliver the last subchain.
        //
        if (!QuicBindingDeliverDatagrams(Binding, SubChain, SubChainLength)) {
            *ReleaseChainTail = SubChain;
            ReleaseChainTail = SubChainTail; // cppcheck-suppress unreadVariable; NOLINT
        }
    }

    if (ReleaseChain != NULL) {
        CxPlatRecvDataReturn(ReleaseChain);
    }

    QuicPerfCounterAdd(QUIC_PERF_COUNTER_UDP_RECV, TotalChainLength);
    QuicPerfCounterAdd(QUIC_PERF_COUNTER_UDP_RECV_BYTES, TotalDatagramBytes);
    QuicPerfCounterIncrement(QUIC_PERF_COUNTER_UDP_RECV_EVENTS);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_UNREACHABLE_CALLBACK)
void
QuicBindingUnreachable(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ void* Context,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    UNREFERENCED_PARAMETER(Socket);
    CXPLAT_DBG_ASSERT(Context != NULL);
    CXPLAT_DBG_ASSERT(RemoteAddress != NULL);

    QUIC_BINDING* Binding = (QUIC_BINDING*)Context;

    QUIC_CONNECTION* Connection =
        QuicLookupFindConnectionByRemoteAddr(
            &Binding->Lookup,
            RemoteAddress);

    if (Connection != NULL) {
        QuicConnQueueUnreachable(Connection, RemoteAddress);
        QuicConnRelease(Connection, QUIC_CONN_REF_LOOKUP_RESULT);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicBindingSend(
    _In_ QUIC_BINDING* Binding,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint32_t BytesToSend,
    _In_ uint32_t DatagramsToSend,
    _In_ uint16_t IdealProcessor
    )
{
    QUIC_STATUS Status;

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    QUIC_TEST_DATAPATH_HOOKS* Hooks = MsQuicLib.TestDatapathHooks;
    if (Hooks != NULL) {

        CXPLAT_ROUTE RouteCopy = *Route;

        BOOLEAN Drop =
            Hooks->Send(
                &RouteCopy.RemoteAddress,
                &RouteCopy.LocalAddress,
                SendData);

        if (Drop) {
            QuicTraceLogVerbose(
                BindingSendTestDrop,
                "[bind][%p] Test dropped packet",
                Binding);
            CxPlatSendDataFree(SendData);
            Status = QUIC_STATUS_SUCCESS;
        } else {
            Status =
                CxPlatSocketSend(
                    Binding->Socket,
                    &RouteCopy,
                    SendData,
                    IdealProcessor);
            if (QUIC_FAILED(Status)) {
                QuicTraceLogWarning(
                    BindingSendFailed,
                    "[bind][%p] Send failed, 0x%x",
                    Binding,
                    Status);
            }
        }
    } else {
#endif
        Status =
            CxPlatSocketSend(
                Binding->Socket,
                Route,
                SendData,
                IdealProcessor);
        if (QUIC_FAILED(Status)) {
            QuicTraceLogWarning(
                BindingSendFailed,
                "[bind][%p] Send failed, 0x%x",
                Binding,
                Status);
        }
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    }
#endif

    QuicPerfCounterAdd(QUIC_PERF_COUNTER_UDP_SEND, DatagramsToSend);
    QuicPerfCounterAdd(QUIC_PERF_COUNTER_UDP_SEND_BYTES, BytesToSend);
    QuicPerfCounterIncrement(QUIC_PERF_COUNTER_UDP_SEND_CALLS);

    return Status;
}
