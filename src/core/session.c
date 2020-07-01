/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A "session" manages TLS session state, which is used for session
    resumption across connections. On Windows it also manages silo
    and network compartment state.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "session.c.clog.h"
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicSessionAlloc(
    _In_opt_ QUIC_REGISTRATION* Registration,
    _In_opt_ void* Context,
    _When_(AlpnBufferCount > 0, _In_reads_(AlpnBufferCount))
    _When_(AlpnBufferCount == 0, _In_opt_)
        const QUIC_BUFFER* const AlpnBuffers,
    _In_ uint32_t AlpnBufferCount,
    _Outptr_ _At_(*NewSession, __drv_allocatesMem(Mem))
        QUIC_SESSION** NewSession
    )
{
    uint32_t AlpnListLength = 0;
    for (uint32_t i = 0; i < AlpnBufferCount; ++i) {
        if (AlpnBuffers[i].Length == 0 ||
            AlpnBuffers[i].Length > QUIC_MAX_ALPN_LENGTH) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        AlpnListLength += sizeof(uint8_t) + AlpnBuffers[i].Length;
    }
    if (AlpnListLength > UINT16_MAX) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    QUIC_ANALYSIS_ASSERT(AlpnListLength <= UINT16_MAX);

    QUIC_SESSION* Session = QUIC_ALLOC_NONPAGED(sizeof(QUIC_SESSION) + AlpnListLength);
    if (Session == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "session" ,
            sizeof(QUIC_SESSION) + AlpnListLength);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    QuicZeroMemory(Session, sizeof(QUIC_SESSION));
    Session->Type = QUIC_HANDLE_TYPE_SESSION;
    Session->ClientContext = Context;
    Session->AlpnListLength = (uint16_t)AlpnListLength;

    uint8_t* AlpnList = Session->AlpnList;
    for (uint32_t i = 0; i < AlpnBufferCount; ++i) {
        AlpnList[0] = (uint8_t)AlpnBuffers[i].Length;
        AlpnList++;

        QuicCopyMemory(
            AlpnList,
            AlpnBuffers[i].Buffer,
            AlpnBuffers[i].Length);
        AlpnList += AlpnBuffers[i].Length;
    }

    if (Registration != NULL) {
        Session->Registration = Registration;

#ifdef QUIC_SILO
        Session->Silo = QuicSiloGetCurrentServer();
        QuicSiloAddRef(Session->Silo);
#endif

#ifdef QUIC_COMPARTMENT_ID
        Session->CompartmentId = QuicCompartmentIdGetCurrent();
#endif
    }

    QuicTraceEvent(
        SessionCreated,
        "[sess][%p] Created, Registration=%p, Alpn=%s",
        Session,
        Session->Registration,
        ""); // TODO - Buffer and length

    QuicRundownInitialize(&Session->Rundown);
    QuicRwLockInitialize(&Session->ServerCacheLock);
    QuicDispatchLockInitialize(&Session->ConnectionsLock);
    QuicListInitializeHead(&Session->Connections);

    *NewSession = Session;

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicSessionFree(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        QUIC_SESSION* Session
    )
{
    //
    // If you hit this assert, you are trying to clean up a session without
    // first cleaning up all the child connections first.
    //
    QUIC_TEL_ASSERT(QuicListIsEmpty(&Session->Connections));
    QuicRundownUninitialize(&Session->Rundown);

    if (Session->Registration != NULL) {
        QuicTlsSessionUninitialize(Session->TlsSession);

        //
        // Enumerate and free all entries in the table.
        //
        QUIC_HASHTABLE_ENTRY* Entry;
        QUIC_HASHTABLE_ENUMERATOR Enumerator;
        QuicHashtableEnumerateBegin(&Session->ServerCache, &Enumerator);
        while (TRUE) {
            Entry = QuicHashtableEnumerateNext(&Session->ServerCache, &Enumerator);
            if (Entry == NULL) {
                QuicHashtableEnumerateEnd(&Session->ServerCache, &Enumerator);
                break;
            }
            QuicHashtableRemove(&Session->ServerCache, Entry, NULL);

            //
            // Release the security config stored in this cache.
            //
            QUIC_SERVER_CACHE* Temp = QUIC_CONTAINING_RECORD(Entry, QUIC_SERVER_CACHE, Entry);
            if (Temp->SecConfig != NULL) {
                QuicTlsSecConfigRelease(Temp->SecConfig);
            }

            QUIC_FREE(Entry);
        }
        QuicHashtableUninitialize(&Session->ServerCache);

        QuicStorageClose(Session->AppSpecificStorage);
#ifdef QUIC_SILO
        QuicStorageClose(Session->Storage);
        QuicSiloRelease(Session->Silo);
#endif
    }

    QuicDispatchLockUninitialize(&Session->ConnectionsLock);
    QuicRwLockUninitialize(&Session->ServerCacheLock);
    QuicTraceEvent(
        SessionDestroyed,
        "[sess][%p] Destroyed",
        Session);
    QUIC_FREE(Session);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicSessionOpen(
    _In_ _Pre_defensive_ HQUIC RegistrationContext,
    _In_reads_(AlpnBufferCount) _Pre_defensive_
        const QUIC_BUFFER* const AlpnBuffers,
    _In_range_(>, 0) uint32_t AlpnBufferCount,
    _In_opt_ void* Context,
    _Outptr_ _At_(*NewSession, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC *NewSession
    )
{
    QUIC_STATUS Status;
    QUIC_SESSION* Session = NULL;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_SESSION_OPEN,
        RegistrationContext);

    if (RegistrationContext == NULL ||
        RegistrationContext->Type != QUIC_HANDLE_TYPE_REGISTRATION ||
        NewSession == NULL ||
        AlpnBufferCount == 0 ||
        AlpnBuffers == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    Status =
        QuicSessionAlloc(
            (QUIC_REGISTRATION*)RegistrationContext,
            Context,
            AlpnBuffers,
            AlpnBufferCount,
            &Session);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (!QuicHashtableInitializeEx(&Session->ServerCache, QUIC_HASH_MIN_SIZE)) {
        QuicTraceEvent(
            SessionError,
            "[sess][%p] ERROR, %s.",
            Session,
            "Server cache initialize");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Status = QuicTlsSessionInitialize(&Session->TlsSession);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            SessionErrorStatus,
            "[sess][%p] ERROR, %u, %s.",
            Session,
            Status,
            "QuicTlsSessionInitialize");
        QuicHashtableUninitialize(&Session->ServerCache);
        goto Error;
    }

#ifdef QUIC_SILO
    if (Session->Silo != NULL) {
        //
        // Only need to load base key if in a silo. Otherwise, the library already
        // read in the default silo settings.
        //
        Status =
            QuicStorageOpen(
                NULL,
                (QUIC_STORAGE_CHANGE_CALLBACK_HANDLER)QuicSessionSettingsChanged,
                Session,
                &Session->Storage);
        if (QUIC_FAILED(Status)) {
            QuicTraceLogWarning(
                SessionOpenStorageFailed,
                "[sess][%p] Failed to open settings, 0x%x",
                Session,
                Status);
            Status = QUIC_STATUS_SUCCESS; // Non-fatal, as the process may not have access
        }
    }
#endif

    if (Session->Registration->AppNameLength != 0) {
        char SpecificAppKey[UINT8_MAX + sizeof(QUIC_SETTING_APP_KEY)] = QUIC_SETTING_APP_KEY;
        QuicCopyMemory(
            SpecificAppKey + sizeof(QUIC_SETTING_APP_KEY) - 1,
            Session->Registration->AppName,
            Session->Registration->AppNameLength);
        Status =
            QuicStorageOpen(
                SpecificAppKey,
                (QUIC_STORAGE_CHANGE_CALLBACK_HANDLER)QuicSessionSettingsChanged,
                Session,
                &Session->AppSpecificStorage);
        if (QUIC_FAILED(Status)) {
            QuicTraceLogWarning(
                SessionOpenAppStorageFailed,
                "[sess][%p] Failed to open app specific settings, 0x%x",
                Session,
                Status);
            Status = QUIC_STATUS_SUCCESS; // Non-fatal, as the process may not have access
        }
    }

    QuicSessionSettingsChanged(Session);

    QuicLockAcquire(&Session->Registration->Lock);
    QuicListInsertTail(&Session->Registration->Sessions, &Session->Link);
    QuicLockRelease(&Session->Registration->Lock);

    *NewSession = (HQUIC)Session;
    Session = NULL;

Error:

    if (Session != NULL) {
        MsQuicSessionFree(Session);
    }

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicSessionClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Handle
    )
{
    if (Handle == NULL) {
        return;
    }

    QUIC_TEL_ASSERT(Handle->Type == QUIC_HANDLE_TYPE_SESSION);
    _Analysis_assume_(Handle->Type == QUIC_HANDLE_TYPE_SESSION);
    if (Handle->Type != QUIC_HANDLE_TYPE_SESSION) {
        return;
    }

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_SESSION_CLOSE,
        Handle);

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    QUIC_SESSION* Session = (QUIC_SESSION*)Handle;

    QuicTraceEvent(
        SessionCleanup,
        "[sess][%p] Cleaning up",
        Session);

    if (Session->Registration != NULL) {
        QuicLockAcquire(&Session->Registration->Lock);
        QuicListEntryRemove(&Session->Link);
        QuicLockRelease(&Session->Registration->Lock);
    } else {
        //
        // This is the global unregistered session. All connections need to be
        // immediately cleaned up. Use shutdown to ensure this all gets placed
        // on the worker queue.
        //
        MsQuicSessionShutdown(Handle, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
    }

    QuicRundownReleaseAndWait(&Session->Rundown);
    MsQuicSessionFree(Session);

    QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicSessionShutdown(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode
    )
{
    QUIC_DBG_ASSERT(Handle != NULL);
    QUIC_DBG_ASSERT(Handle->Type == QUIC_HANDLE_TYPE_SESSION);

    if (ErrorCode > QUIC_UINT62_MAX) {
        return;
    }

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_SESSION_SHUTDOWN,
        Handle);

    if (Handle && Handle->Type == QUIC_HANDLE_TYPE_SESSION) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_SESSION* Session = (QUIC_SESSION*)Handle;

        QuicTraceEvent(
            SessionShutdown,
            "[sess][%p] Shutting down connections, Flags=%u, ErrorCode=%llu",
            Session,
            Flags,
            ErrorCode);

        QuicDispatchLockAcquire(&Session->ConnectionsLock);

        QUIC_LIST_ENTRY* Entry = Session->Connections.Flink;
        while (Entry != &Session->Connections) {

            QUIC_CONNECTION* Connection =
                QUIC_CONTAINING_RECORD(Entry, QUIC_CONNECTION, SessionLink);

            if (InterlockedCompareExchange16(
                    (short*)&Connection->BackUpOperUsed, 1, 0) == 0) {

                QUIC_OPERATION* Oper = &Connection->BackUpOper;
                Oper->FreeAfterProcess = FALSE;
                Oper->Type = QUIC_OPER_TYPE_API_CALL;
                Oper->API_CALL.Context = &Connection->BackupApiContext;
                Oper->API_CALL.Context->Type = QUIC_API_TYPE_CONN_SHUTDOWN;
                Oper->API_CALL.Context->CONN_SHUTDOWN.Flags = Flags;
                Oper->API_CALL.Context->CONN_SHUTDOWN.ErrorCode = ErrorCode;
                QuicConnQueueHighestPriorityOper(Connection, Oper);
            }

            Entry = Entry->Flink;
        }

        QuicDispatchLockRelease(&Session->ConnectionsLock);
    }

    QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
}

_IRQL_requires_max_(DISPATCH_LEVEL)
const uint8_t*
QuicSessionFindAlpnInList(
    _In_ const QUIC_SESSION* Session,
    _In_ uint16_t OtherAlpnListLength,
    _In_reads_(OtherAlpnListLength)
        const uint8_t* OtherAlpnList
    )
{
    const uint8_t* AlpnList = Session->AlpnList;
    uint16_t AlpnListLength = Session->AlpnListLength;

    //
    // We want to respect the server's ALPN preference order (i.e. Session) and
    // not the client's. So we loop over every ALPN in the session and then see
    // if there is a match in the client's list.
    //

    while (AlpnListLength != 0) {
        QUIC_ANALYSIS_ASSUME(AlpnList[0] + 1 <= AlpnListLength);
        const uint8_t* Result =
            QuicTlsAlpnFindInList(
                OtherAlpnListLength,
                OtherAlpnList,
                AlpnList[0],
                AlpnList + 1);
        if (Result != NULL) {
            //
            // Return AlpnList instead of Result, since Result points into what
            // might be a temporary buffer.
            //
            return AlpnList;
        }
        AlpnListLength -= AlpnList[0] + 1;
        AlpnList += AlpnList[0] + 1;
    }

    return NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicSessionHasAlpnOverlap(
    _In_ const QUIC_SESSION* Session1,
    _In_ const QUIC_SESSION* Session2
    )
{
    return
        QuicSessionFindAlpnInList(
            Session1,
            Session2->AlpnListLength,
            Session2->AlpnList) != NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicSessionMatchesAlpn(
    _In_ const QUIC_SESSION* Session,
    _In_ QUIC_NEW_CONNECTION_INFO* Info
    )
{
    const uint8_t* Alpn =
        QuicSessionFindAlpnInList(Session, Info->ClientAlpnListLength, Info->ClientAlpnList);
    if (Alpn != NULL) {
        Info->NegotiatedAlpnLength = Alpn[0]; // The length prefixed to the ALPN buffer.
        Info->NegotiatedAlpn = Alpn + 1;
        return TRUE;
    }
    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSessionTraceRundown(
    _In_ QUIC_SESSION* Session
    )
{
    QuicTraceEvent(
        SessionRundown,
        "[sess][%p] Rundown, Registration=%p, Alpn=%p",
        Session,
        Session->Registration,
        ""); // TODO

    QuicDispatchLockAcquire(&Session->ConnectionsLock);

    for (QUIC_LIST_ENTRY* Link = Session->Connections.Flink;
        Link != &Session->Connections;
        Link = Link->Flink) {
        QuicConnQueueTraceRundown(
            QUIC_CONTAINING_RECORD(Link, QUIC_CONNECTION, SessionLink));
    }

    QuicDispatchLockRelease(&Session->ConnectionsLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_STORAGE_CHANGE_CALLBACK)
void
QuicSessionSettingsChanged(
    _Inout_ QUIC_SESSION* Session
    )
{
#ifdef QUIC_SILO
    if (Session->Storage != NULL) {
        QuicSettingsSetDefault(&Session->Settings);
        QuicSettingsLoad(&Session->Settings, Session->Storage);
    } else {
        QuicSettingsCopy(&Session->Settings, &MsQuicLib.Settings);
    }
#else
    QuicSettingsCopy(&Session->Settings, &MsQuicLib.Settings);
#endif

    if (Session->AppSpecificStorage != NULL) {
        QuicSettingsLoad(&Session->Settings, Session->AppSpecificStorage);
    }

    QuicTraceLogInfo(
        SessionSettingsUpdated,
        "[sess][%p] Settings %p Updated",
        Session,
        &Session->Settings);
    QuicSettingsDump(&Session->Settings);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSessionRegisterConnection(
    _Inout_ QUIC_SESSION* Session,
    _Inout_ QUIC_CONNECTION* Connection
    )
{
    QuicSessionUnregisterConnection(Connection);
    Connection->Session = Session;

    if (Session->Registration != NULL) {
        Connection->Registration = Session->Registration;
        QuicRundownAcquire(&Session->Registration->ConnectionRundown);
#ifdef QuicVerifierEnabledByAddr
        Connection->State.IsVerifying = Session->Registration->IsVerifying;
#endif
        QuicConnApplySettings(Connection, &Session->Settings);
    }

    QuicTraceEvent(
        ConnRegisterSession,
        "[conn][%p] Registered with session: %p",
        Connection,
        Session);
    BOOLEAN Success = QuicRundownAcquire(&Session->Rundown);
    QUIC_DBG_ASSERT(Success); UNREFERENCED_PARAMETER(Success);
    QuicDispatchLockAcquire(&Session->ConnectionsLock);
    QuicListInsertTail(&Session->Connections, &Connection->SessionLink);
    QuicDispatchLockRelease(&Session->ConnectionsLock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSessionUnregisterConnection(
    _Inout_ QUIC_CONNECTION* Connection
    )
{
    if (Connection->Session == NULL) {
        return;
    }
    QUIC_SESSION* Session = Connection->Session;
    Connection->Session = NULL;
    QuicTraceEvent(
        ConnUnregisterSession,
        "[conn][%p] Unregistered from session: %p",
        Connection,
        Session);
    QuicDispatchLockAcquire(&Session->ConnectionsLock);
    QuicListEntryRemove(&Connection->SessionLink);
    QuicDispatchLockRelease(&Session->ConnectionsLock);
    QuicRundownRelease(&Session->Rundown);
}

//
// Requires Session->Lock to be held (shared or exclusive).
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_SERVER_CACHE*
QuicSessionServerCacheLookup(
    _In_ QUIC_SESSION* Session,
    _In_ uint16_t ServerNameLength,
    _In_reads_(ServerNameLength)
        const char* ServerName,
    _In_ uint32_t Hash
    )
{
    QUIC_HASHTABLE_LOOKUP_CONTEXT Context;
    QUIC_HASHTABLE_ENTRY* Entry =
        QuicHashtableLookup(&Session->ServerCache, Hash, &Context);

    while (Entry != NULL) {
        QUIC_SERVER_CACHE* Temp =
            QUIC_CONTAINING_RECORD(Entry, QUIC_SERVER_CACHE, Entry);
        if (Temp->ServerNameLength == ServerNameLength &&
            memcmp(Temp->ServerName, ServerName, ServerNameLength) == 0) {
            return Temp;
        }
        Entry = QuicHashtableLookupNext(&Session->ServerCache, &Context);
    }

    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicSessionServerCacheGetState(
    _In_ QUIC_SESSION* Session,
    _In_z_ const char* ServerName,
    _Out_ uint32_t* QuicVersion,
    _Out_ QUIC_TRANSPORT_PARAMETERS* Parameters,
    _Out_ QUIC_SEC_CONFIG** ClientSecConfig
    )
{
    uint16_t ServerNameLength = (uint16_t)strlen(ServerName);
    uint32_t Hash = QuicHashSimple(ServerNameLength, (const uint8_t*)ServerName);

    QuicRwLockAcquireShared(&Session->ServerCacheLock);

    QUIC_SERVER_CACHE* Cache =
        QuicSessionServerCacheLookup(
            Session,
            ServerNameLength,
            ServerName,
            Hash);

    if (Cache != NULL) {
        *QuicVersion = Cache->QuicVersion;
        *Parameters = Cache->TransportParameters;
        if (Cache->SecConfig != NULL) {
            *ClientSecConfig = QuicTlsSecConfigAddRef(Cache->SecConfig);
        } else {
            *ClientSecConfig = NULL;
        }
    }

    QuicRwLockReleaseShared(&Session->ServerCacheLock);

    return Cache != NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSessionServerCacheSetStateInternal(
    _In_ QUIC_SESSION* Session,
    _In_ uint16_t ServerNameLength,
    _In_reads_(ServerNameLength)
        const char* ServerName,
    _In_ uint32_t QuicVersion,
    _In_ const QUIC_TRANSPORT_PARAMETERS* Parameters,
    _In_opt_ QUIC_SEC_CONFIG* SecConfig
    )
{
    uint32_t Hash = QuicHashSimple(ServerNameLength, (const uint8_t*)ServerName);

    QuicRwLockAcquireExclusive(&Session->ServerCacheLock);

    QUIC_SERVER_CACHE* Cache =
        QuicSessionServerCacheLookup(
            Session,
            ServerNameLength,
            ServerName,
            Hash);

    if (Cache != NULL) {
        Cache->QuicVersion = QuicVersion;
        Cache->TransportParameters = *Parameters;
        if (SecConfig != NULL) {
            if (Cache->SecConfig != NULL) {
                QuicTlsSecConfigRelease(Cache->SecConfig);
            }
            Cache->SecConfig = QuicTlsSecConfigAddRef(SecConfig);
        }

    } else {
#pragma prefast(suppress: __WARNING_6014, "Memory is correctly freed (MsQuicSessionClose).")
        Cache = QUIC_ALLOC_PAGED(sizeof(QUIC_SERVER_CACHE) + ServerNameLength);

        if (Cache != NULL) {
            memcpy(Cache + 1, ServerName, ServerNameLength);
            Cache->ServerName = (const char*)(Cache + 1);
            Cache->ServerNameLength = ServerNameLength;
            Cache->QuicVersion = QuicVersion;
            Cache->TransportParameters = *Parameters;
            if (SecConfig != NULL) {
                Cache->SecConfig = QuicTlsSecConfigAddRef(SecConfig);
            }

            QuicHashtableInsert(&Session->ServerCache, &Cache->Entry, Hash, NULL);

        } else {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "server cache entry",
                sizeof(QUIC_SERVER_CACHE) + ServerNameLength);
        }
    }

    QuicRwLockReleaseExclusive(&Session->ServerCacheLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSessionServerCacheSetState(
    _In_ QUIC_SESSION* Session,
    _In_z_ const char* ServerName,
    _In_ uint32_t QuicVersion,
    _In_ const QUIC_TRANSPORT_PARAMETERS* Parameters,
    _In_ QUIC_SEC_CONFIG* SecConfig
    )
{
    QuicSessionServerCacheSetStateInternal(
        Session,
        (uint16_t)strlen(ServerName),
        ServerName,
        QuicVersion,
        Parameters,
        SecConfig);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSessionParamGet(
    _In_ QUIC_SESSION* Session,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;

    switch (Param) {

    case QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT:

        if (*BufferLength < sizeof(Session->Settings.BidiStreamCount)) {
            *BufferLength = sizeof(Session->Settings.BidiStreamCount);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Session->Settings.BidiStreamCount);
        *(uint16_t*)Buffer = Session->Settings.BidiStreamCount;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_SESSION_PEER_UNIDI_STREAM_COUNT:

        if (*BufferLength < sizeof(Session->Settings.UnidiStreamCount)) {
            *BufferLength = sizeof(Session->Settings.UnidiStreamCount);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Session->Settings.UnidiStreamCount);
        *(uint16_t*)Buffer = Session->Settings.UnidiStreamCount;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_SESSION_IDLE_TIMEOUT:

        if (*BufferLength < sizeof(Session->Settings.IdleTimeoutMs)) {
            *BufferLength = sizeof(Session->Settings.IdleTimeoutMs);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Session->Settings.IdleTimeoutMs);
        *(uint64_t*)Buffer = Session->Settings.IdleTimeoutMs;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_SESSION_DISCONNECT_TIMEOUT:

        if (*BufferLength < sizeof(Session->Settings.DisconnectTimeoutMs)) {
            *BufferLength = sizeof(Session->Settings.DisconnectTimeoutMs);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Session->Settings.DisconnectTimeoutMs);
        *(uint32_t*)Buffer = Session->Settings.DisconnectTimeoutMs;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_SESSION_MAX_BYTES_PER_KEY:
        if (*BufferLength < sizeof(Session->Settings.MaxBytesPerKey)) {
            *BufferLength = sizeof(Session->Settings.MaxBytesPerKey);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Session->Settings.MaxBytesPerKey);
        *(uint64_t*)Buffer = Session->Settings.MaxBytesPerKey;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_SESSION_MIGRATION_ENABLED:
        if (*BufferLength < sizeof(BOOLEAN)) {
            *BufferLength = sizeof(BOOLEAN);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(BOOLEAN);
        *(BOOLEAN*)Buffer = Session->Settings.MigrationEnabled;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_SESSION_DATAGRAM_RECEIVE_ENABLED:
        if (*BufferLength < sizeof(BOOLEAN)) {
            *BufferLength = sizeof(BOOLEAN);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(BOOLEAN);
        *(BOOLEAN*)Buffer = Session->Settings.DatagramReceiveEnabled;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_SESSION_SERVER_RESUMPTION_LEVEL:
        if (*BufferLength  < sizeof(QUIC_SERVER_RESUMPTION_LEVEL)) {
            *BufferLength = sizeof(QUIC_SERVER_RESUMPTION_LEVEL);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(QUIC_SERVER_RESUMPTION_LEVEL);
        *(QUIC_SERVER_RESUMPTION_LEVEL*)Buffer =
            (QUIC_SERVER_RESUMPTION_LEVEL)Session->Settings.ServerResumptionLevel;

        Status = QUIC_STATUS_SUCCESS;
        break;

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSessionParamSet(
    _In_ QUIC_SESSION* Session,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    QUIC_STATUS Status;

    switch (Param) {

    case QUIC_PARAM_SESSION_TLS_TICKET_KEY: {

        if (BufferLength != 44) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Status =
            QuicTlsSessionSetTicketKey(
                Session->TlsSession,
                Buffer);
        break;
    }

    case QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT: {

        if (BufferLength != sizeof(uint16_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Session->Settings.AppSet.BidiStreamCount = TRUE;
        Session->Settings.BidiStreamCount = *(uint16_t*)Buffer;

        QuicTraceLogInfo(
            SessionBiDiStreamCountSet,
            "[sess][%p] Updated bidirectional stream count = %hu",
            Session,
            Session->Settings.BidiStreamCount);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_SESSION_PEER_UNIDI_STREAM_COUNT: {

        if (BufferLength != sizeof(uint16_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Session->Settings.AppSet.UnidiStreamCount = TRUE;
        Session->Settings.UnidiStreamCount = *(uint16_t*)Buffer;

        QuicTraceLogInfo(
            SessionUniDiStreamCountSet,
            "[sess][%p] Updated unidirectional stream count = %hu",
            Session,
            Session->Settings.UnidiStreamCount);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_SESSION_IDLE_TIMEOUT: {

        if (BufferLength != sizeof(Session->Settings.IdleTimeoutMs)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Session->Settings.AppSet.IdleTimeoutMs = TRUE;
        Session->Settings.IdleTimeoutMs = *(uint64_t*)Buffer;

        QuicTraceLogInfo(
            SessionIdleTimeoutSet,
            "[sess][%p] Updated idle timeout to %llu milliseconds",
            Session,
            Session->Settings.IdleTimeoutMs);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_SESSION_DISCONNECT_TIMEOUT: {

        if (BufferLength != sizeof(Session->Settings.DisconnectTimeoutMs)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Session->Settings.AppSet.DisconnectTimeoutMs = TRUE;
        Session->Settings.DisconnectTimeoutMs = *(uint32_t*)Buffer;

        QuicTraceLogInfo(
            SessionDisconnectTimeoutSet,
            "[sess][%p] Updated disconnect timeout to %u milliseconds",
            Session,
            Session->Settings.DisconnectTimeoutMs);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_SESSION_ADD_RESUMPTION_STATE: {

        const QUIC_SERIALIZED_RESUMPTION_STATE* State =
            (const QUIC_SERIALIZED_RESUMPTION_STATE*)Buffer;

        if (BufferLength < sizeof(QUIC_SERIALIZED_RESUMPTION_STATE) ||
            BufferLength < sizeof(QUIC_SERIALIZED_RESUMPTION_STATE) + State->ServerNameLength) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        const char* ServerName = (const char*)State->Buffer;

        const uint8_t* TicketBuffer = State->Buffer + State->ServerNameLength;
        uint32_t TicketBufferLength =
            BufferLength -
            sizeof(QUIC_SERIALIZED_RESUMPTION_STATE) -
            State->ServerNameLength;

        QuicSessionServerCacheSetStateInternal(
            Session,
            State->ServerNameLength,
            ServerName,
            State->QuicVersion,
            &State->TransportParameters,
            NULL);

        Status =
            QuicTlsSessionAddTicket(
                Session->TlsSession,
                TicketBufferLength,
                TicketBuffer);
        break;
    }

    case QUIC_PARAM_SESSION_MAX_BYTES_PER_KEY: {
        if (BufferLength != sizeof(Session->Settings.MaxBytesPerKey)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        uint64_t NewValue = *(uint64_t*)Buffer;
        if (NewValue > QUIC_DEFAULT_MAX_BYTES_PER_KEY) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Session->Settings.AppSet.MaxBytesPerKey = TRUE;
        Session->Settings.MaxBytesPerKey = NewValue;

        QuicTraceLogInfo(
            SessionMaxBytesPerKeySet,
            "[sess][%p] Updated max bytes per key to %llu bytes",
            Session,
            Session->Settings.MaxBytesPerKey);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_SESSION_MIGRATION_ENABLED: {
        if (BufferLength != sizeof(BOOLEAN)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Session->Settings.AppSet.MigrationEnabled = TRUE;
        Session->Settings.MigrationEnabled = *(BOOLEAN*)Buffer;

        QuicTraceLogInfo(
            SessionMigrationEnabledSet,
            "[sess][%p] Updated migration enabled to %hhu",
            Session,
            Session->Settings.MigrationEnabled);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_SESSION_DATAGRAM_RECEIVE_ENABLED: {
        if (BufferLength != sizeof(BOOLEAN)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Session->Settings.AppSet.DatagramReceiveEnabled = TRUE;
        Session->Settings.DatagramReceiveEnabled = *(BOOLEAN*)Buffer;

        QuicTraceLogInfo(
            SessionDatagramReceiveEnabledSet,
            "[sess][%p] Updated datagram receive enabled to %hhu",
            Session,
            Session->Settings.DatagramReceiveEnabled);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_SESSION_SERVER_RESUMPTION_LEVEL: {
        if (BufferLength != sizeof(QUIC_SERVER_RESUMPTION_LEVEL) ||
            Buffer == NULL ||
            *(QUIC_SERVER_RESUMPTION_LEVEL*)Buffer > QUIC_SERVER_RESUME_AND_ZERORTT) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Session->Settings.AppSet.ServerResumptionLevel = TRUE;
        Session->Settings.ServerResumptionLevel =
            *(QUIC_SERVER_RESUMPTION_LEVEL*)Buffer;

        QuicTraceLogInfo(
            SessionServerResumptionLevelSet,
            "[sess][%p] Updated Server resume/0-RTT to %hhu",
            Session,
            Session->Settings.ServerResumptionLevel);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}
