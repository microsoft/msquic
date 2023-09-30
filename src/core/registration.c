/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The registration is the highest layer in the QUIC object hierarchy. It
    maintains all the application's execution context. This mainly consists of
    a set of worker threads to drive all the connections that are specific to
    the application context.

    The number of worker threads is dependent on the total number of processors
    in the system. The set of connections managed by the registration are
    partitioned as equally as possible among these worker threads.

    Each worker thread is responsible for calling QuicConnDrainOperations to
    allow the connections to process any work that they currently have queued.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "registration.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicRegistrationOpen(
    _In_opt_ const QUIC_REGISTRATION_CONFIG* Config,
    _Outptr_ _At_(*NewRegistration, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* NewRegistration
    )
{
    QUIC_STATUS Status;
    QUIC_REGISTRATION* Registration = NULL;
    const BOOLEAN ExternalRegistration =
        Config == NULL || Config->ExecutionProfile != QUIC_EXECUTION_PROFILE_TYPE_INTERNAL;
    const size_t AppNameLength =
        (Config != NULL && Config->AppName != NULL) ? strlen(Config->AppName) : 0;
    const size_t RegistrationSize = sizeof(QUIC_REGISTRATION) + AppNameLength + 1;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_REGISTRATION_OPEN,
        NULL);

    if (NewRegistration == NULL || AppNameLength >= UINT8_MAX) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    //
    // For external registrations, we need to take the library lock. For the internal
    // registration, the caller of this function holds the lock.
    //
    Status = QuicLibraryLazyInitialize(ExternalRegistration);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Registration = CXPLAT_ALLOC_NONPAGED(RegistrationSize, QUIC_POOL_REGISTRATION);
    if (Registration == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "registration",
            sizeof(QUIC_REGISTRATION) + AppNameLength + 1);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    CxPlatZeroMemory(Registration, RegistrationSize);
    Registration->Type = QUIC_HANDLE_TYPE_REGISTRATION;
    Registration->ExecProfile =
        Config == NULL ? QUIC_EXECUTION_PROFILE_LOW_LATENCY : Config->ExecutionProfile;
    Registration->NoPartitioning =
        Registration->ExecProfile == QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER;
    CxPlatLockInitialize(&Registration->ConfigLock);
    CxPlatListInitializeHead(&Registration->Configurations);
    CxPlatDispatchLockInitialize(&Registration->ConnectionLock);
    CxPlatListInitializeHead(&Registration->Connections);
    CxPlatListInitializeHead(&Registration->Listeners);
    CxPlatRundownInitialize(&Registration->Rundown);
    Registration->AppNameLength = (uint8_t)(AppNameLength + 1);
    if (AppNameLength != 0) {
        CxPlatCopyMemory(Registration->AppName, Config->AppName, AppNameLength + 1);
    }

    Status =
        QuicWorkerPoolInitialize(
            Registration, Registration->ExecProfile, &Registration->WorkerPool);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    QuicTraceEvent(
        RegistrationCreatedV2,
        "[ reg][%p] Created, AppName=%s, ExecProfile=%u",
        Registration,
        Registration->AppName,
        Registration->ExecProfile);

#ifdef CxPlatVerifierEnabledByAddr
#pragma prefast(suppress:6001, "SAL doesn't understand checking whether memory is tracked by Verifier.")
    if (MsQuicLib.IsVerifying &&
        CxPlatVerifierEnabledByAddr(NewRegistration)) {
        Registration->IsVerifying = TRUE;
        QuicTraceLogInfo(
            RegistrationVerifierEnabled,
            "[ reg][%p] Verifing enabled!",
            Registration);
    } else {
        Registration->IsVerifying = FALSE;
    }
#endif

    if (ExternalRegistration) {
        CxPlatLockAcquire(&MsQuicLib.Lock);
        CxPlatListInsertTail(&MsQuicLib.Registrations, &Registration->Link);
        CxPlatLockRelease(&MsQuicLib.Lock);
    }

    *NewRegistration = (HQUIC)Registration;
    Registration = NULL;

Error:

    if (Registration != NULL) {
        CxPlatRundownUninitialize(&Registration->Rundown);
        CxPlatDispatchLockUninitialize(&Registration->ConnectionLock);
        CxPlatLockUninitialize(&Registration->ConfigLock);
        CXPLAT_FREE(Registration, QUIC_POOL_REGISTRATION);
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
MsQuicRegistrationClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Handle
    )
{
    if (Handle != NULL && Handle->Type == QUIC_HANDLE_TYPE_REGISTRATION) {
        QuicTraceEvent(
            ApiEnter,
            "[ api] Enter %u (%p).",
            QUIC_TRACE_API_REGISTRATION_CLOSE,
            Handle);

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_REGISTRATION* Registration = (QUIC_REGISTRATION*)Handle;

        QuicTraceEvent(
            RegistrationCleanup,
            "[ reg][%p] Cleaning up",
            Registration);

        if (Registration->ExecProfile != QUIC_EXECUTION_PROFILE_TYPE_INTERNAL) {
            CxPlatLockAcquire(&MsQuicLib.Lock);
            CxPlatListEntryRemove(&Registration->Link);
            CxPlatLockRelease(&MsQuicLib.Lock);
        }

        CxPlatRundownReleaseAndWait(&Registration->Rundown);

        QuicWorkerPoolUninitialize(Registration->WorkerPool);
        CxPlatRundownUninitialize(&Registration->Rundown);
        CxPlatDispatchLockUninitialize(&Registration->ConnectionLock);
        CxPlatLockUninitialize(&Registration->ConfigLock);

        CXPLAT_FREE(Registration, QUIC_POOL_REGISTRATION);

        QuicTraceEvent(
            ApiExit,
            "[ api] Exit");
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QUIC_API
MsQuicRegistrationShutdown(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode
    )
{
    CXPLAT_DBG_ASSERT(Handle != NULL);
    CXPLAT_DBG_ASSERT(Handle->Type == QUIC_HANDLE_TYPE_REGISTRATION);

    if (ErrorCode > QUIC_UINT62_MAX) {
        return;
    }

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_REGISTRATION_SHUTDOWN,
        Handle);

    if (Handle && Handle->Type == QUIC_HANDLE_TYPE_REGISTRATION) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_REGISTRATION* Registration = (QUIC_REGISTRATION*)Handle;

        CxPlatDispatchLockAcquire(&Registration->ConnectionLock);

        if (Registration->ShuttingDown) {
            CxPlatDispatchLockRelease(&Registration->ConnectionLock);
            goto Exit;
        }

        Registration->ShutdownErrorCode = ErrorCode;
        Registration->ShutdownFlags = Flags;
        Registration->ShuttingDown = TRUE;

        CXPLAT_LIST_ENTRY* Entry = Registration->Connections.Flink;
        while (Entry != &Registration->Connections) {

            QUIC_CONNECTION* Connection =
                CXPLAT_CONTAINING_RECORD(Entry, QUIC_CONNECTION, RegistrationLink);

            if (InterlockedCompareExchange16(
                    (short*)&Connection->BackUpOperUsed, 1, 0) == 0) {

                QUIC_OPERATION* Oper = &Connection->BackUpOper;
                Oper->FreeAfterProcess = FALSE;
                Oper->Type = QUIC_OPER_TYPE_API_CALL;
                Oper->API_CALL.Context = &Connection->BackupApiContext;
                Oper->API_CALL.Context->Type = QUIC_API_TYPE_CONN_SHUTDOWN;
                Oper->API_CALL.Context->CONN_SHUTDOWN.Flags = Flags;
                Oper->API_CALL.Context->CONN_SHUTDOWN.ErrorCode = ErrorCode;
                Oper->API_CALL.Context->CONN_SHUTDOWN.RegistrationShutdown = TRUE;
                Oper->API_CALL.Context->CONN_SHUTDOWN.TransportShutdown = FALSE;
                QuicConnQueueHighestPriorityOper(Connection, Oper);
            }

            Entry = Entry->Flink;
        }

        CxPlatDispatchLockRelease(&Registration->ConnectionLock);

        Entry = Registration->Listeners.Flink;
        while (Entry != &Registration->Listeners) {
            QUIC_LISTENER* Listener =
                CXPLAT_CONTAINING_RECORD(Entry, QUIC_LISTENER, RegistrationLink);
            Entry = Entry->Flink;
            MsQuicListenerStop((HQUIC)Listener);
        }
    }

Exit:

    QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicRegistrationTraceRundown(
    _In_ QUIC_REGISTRATION* Registration
    )
{
    QuicTraceEvent(
        RegistrationRundownV2,
        "[ reg][%p] Rundown, AppName=%s, ExecProfile=%u",
        Registration,
        Registration->AppName,
        Registration->ExecProfile);

    CxPlatLockAcquire(&Registration->ConfigLock);

    for (CXPLAT_LIST_ENTRY* Link = Registration->Configurations.Flink;
        Link != &Registration->Configurations;
        Link = Link->Flink) {
        QuicConfigurationTraceRundown(
            CXPLAT_CONTAINING_RECORD(Link, QUIC_CONFIGURATION, Link));
    }

    CxPlatLockRelease(&Registration->ConfigLock);

    CxPlatDispatchLockAcquire(&Registration->ConnectionLock);

    for (CXPLAT_LIST_ENTRY* Link = Registration->Connections.Flink;
        Link != &Registration->Connections;
        Link = Link->Flink) {
        QuicConnQueueTraceRundown(
            CXPLAT_CONTAINING_RECORD(Link, QUIC_CONNECTION, RegistrationLink));
    }

    CxPlatDispatchLockRelease(&Registration->ConnectionLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicRegistrationSettingsChanged(
    _Inout_ QUIC_REGISTRATION* Registration
    )
{
    CxPlatLockAcquire(&Registration->ConfigLock);

    for (CXPLAT_LIST_ENTRY* Link = Registration->Configurations.Flink;
        Link != &Registration->Configurations;
        Link = Link->Flink) {
        QuicConfigurationSettingsChanged(
            CXPLAT_CONTAINING_RECORD(Link, QUIC_CONFIGURATION, Link));
    }

    CxPlatLockRelease(&Registration->ConfigLock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRegistrationAcceptConnection(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ QUIC_CONNECTION* Connection
    )
{
    const uint16_t Index =
        Registration->NoPartitioning ? 0 : QuicPartitionIdGetIndex(Connection->PartitionID);

    //
    // TODO - Look for other worker instead if the proposed worker is overloaded?
    //

    return !QuicWorkerIsOverloaded(&Registration->WorkerPool->Workers[Index]);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRegistrationQueueNewConnection(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ QUIC_CONNECTION* Connection
    )
{
    uint16_t Index =
        Registration->NoPartitioning ? 0 : QuicPartitionIdGetIndex(Connection->PartitionID);

    //
    // TODO - Look for other worker instead if the proposed worker is overloaded?
    //

    QuicWorkerAssignConnection(
        &Registration->WorkerPool->Workers[Index],
        Connection);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicRegistrationParamSet(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    UNREFERENCED_PARAMETER(Registration);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_INVALID_PARAMETER;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicRegistrationParamGet(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    UNREFERENCED_PARAMETER(Registration);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_INVALID_PARAMETER;
}
