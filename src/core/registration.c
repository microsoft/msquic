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
    size_t AppNameLength = 0;
    if (Config != NULL && Config->AppName != NULL) {
        AppNameLength = strlen(Config->AppName);
    }

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_REGISTRATION_OPEN,
        NULL);

    if (NewRegistration == NULL || AppNameLength >= UINT8_MAX) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    Registration =
        QUIC_ALLOC_NONPAGED(
            sizeof(QUIC_REGISTRATION) + AppNameLength + 1,
            QUIC_POOL_REGISTRATION);
    if (Registration == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "registration",
            sizeof(QUIC_REGISTRATION) + AppNameLength + 1);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Registration->Type = QUIC_HANDLE_TYPE_REGISTRATION;
    Registration->ClientContext = NULL;
    Registration->NoPartitioning = FALSE;
    Registration->SplitPartitioning = FALSE;
    Registration->ExecProfile = Config == NULL ? QUIC_EXECUTION_PROFILE_LOW_LATENCY : Config->ExecutionProfile;
    Registration->CidPrefixLength = 0;
    Registration->CidPrefix = NULL;
    QuicLockInitialize(&Registration->ConfigLock);
    QuicListInitializeHead(&Registration->Configurations);
    QuicDispatchLockInitialize(&Registration->ConnectionLock);
    QuicListInitializeHead(&Registration->Connections);
    QuicRundownInitialize(&Registration->Rundown);
    Registration->AppNameLength = (uint8_t)(AppNameLength + 1);
    if (AppNameLength != 0) {
        QuicCopyMemory(Registration->AppName, Config->AppName, AppNameLength + 1);
    } else {
        Registration->AppName[0] = '\0';
    }

    uint16_t WorkerThreadFlags = 0;
    switch (Registration->ExecProfile) {
    default:
    case QUIC_EXECUTION_PROFILE_LOW_LATENCY:
        WorkerThreadFlags = QUIC_THREAD_FLAG_NONE;
        break;
    case QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT:
        WorkerThreadFlags =
            QUIC_THREAD_FLAG_SET_AFFINITIZE;
        Registration->SplitPartitioning = TRUE;
        break;
    case QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER:
        WorkerThreadFlags = 0;
        Registration->NoPartitioning = TRUE;
        break;
    case QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME:
        WorkerThreadFlags =
            QUIC_THREAD_FLAG_SET_AFFINITIZE;
        break;
    }

    //
    // TODO - Figure out how to check to see if hyper-threading was enabled
    // first
    // When hyper-threading is enabled, better bulk throughput can sometimes
    // be gained by sharing the same physical core, but not the logical one.
    // The shared one is always one greater than the RSS core.
    //
    if (Registration->SplitPartitioning &&
        MsQuicLib.PartitionCount <= QUIC_MAX_THROUGHPUT_PARTITION_OFFSET) {
        Registration->SplitPartitioning = FALSE; // Not enough partitions.
    }

    Status =
        QuicWorkerPoolInitialize(
            Registration,
            WorkerThreadFlags,
            Registration->NoPartitioning ? 1 : MsQuicLib.PartitionCount,
            &Registration->WorkerPool);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    QuicTraceEvent(
        RegistrationCreated,
        "[ reg][%p] Created, AppName=%s",
        Registration,
        Registration->AppName);

#ifdef QuicVerifierEnabledByAddr
#pragma prefast(suppress:6001, "SAL doesn't understand checking whether memory is tracked by Verifier.")
    if (MsQuicLib.IsVerifying &&
        QuicVerifierEnabledByAddr(NewRegistration)) {
        Registration->IsVerifying = TRUE;
        QuicTraceLogInfo(
            RegistrationVerifierEnabled,
            "[ reg][%p] Verifing enabled!",
            Registration);
    } else {
        Registration->IsVerifying = FALSE;
    }
#endif

    if (Registration->ExecProfile != QUIC_EXECUTION_PROFILE_TYPE_INTERNAL) {
        QuicLockAcquire(&MsQuicLib.Lock);
        QuicListInsertTail(&MsQuicLib.Registrations, &Registration->Link);
        QuicLockRelease(&MsQuicLib.Lock);
    }

    *NewRegistration = (HQUIC)Registration;
    Registration = NULL;

Error:

    if (Registration != NULL) {
        QuicRundownUninitialize(&Registration->Rundown);
        QuicDispatchLockUninitialize(&Registration->ConnectionLock);
        QuicLockUninitialize(&Registration->ConfigLock);
        QUIC_FREE(Registration, QUIC_POOL_REGISTRATION);
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
            QuicLockAcquire(&MsQuicLib.Lock);
            QuicListEntryRemove(&Registration->Link);
            QuicLockRelease(&MsQuicLib.Lock);
        }

        QuicRundownReleaseAndWait(&Registration->Rundown);

        QuicWorkerPoolUninitialize(Registration->WorkerPool);
        QuicRundownUninitialize(&Registration->Rundown);
        QuicDispatchLockUninitialize(&Registration->ConnectionLock);
        QuicLockUninitialize(&Registration->ConfigLock);

        if (Registration->CidPrefix != NULL) {
            QUIC_FREE(Registration->CidPrefix, QUIC_POOL_CIDPREFIX);
        }

        QUIC_FREE(Registration, QUIC_POOL_REGISTRATION);

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
    QUIC_DBG_ASSERT(Handle != NULL);
    QUIC_DBG_ASSERT(Handle->Type == QUIC_HANDLE_TYPE_REGISTRATION);

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

        QuicDispatchLockAcquire(&Registration->ConnectionLock);

        QUIC_LIST_ENTRY* Entry = Registration->Connections.Flink;
        while (Entry != &Registration->Connections) {

            QUIC_CONNECTION* Connection =
                QUIC_CONTAINING_RECORD(Entry, QUIC_CONNECTION, RegistrationLink);

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

        QuicDispatchLockRelease(&Registration->ConnectionLock);
    }

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
        RegistrationRundown,
        "[ reg][%p] Rundown, AppName=%s",
        Registration,
        Registration->AppName);

    QuicLockAcquire(&Registration->ConfigLock);

    for (QUIC_LIST_ENTRY* Link = Registration->Configurations.Flink;
        Link != &Registration->Configurations;
        Link = Link->Flink) {
        QuicConfigurationTraceRundown(
            QUIC_CONTAINING_RECORD(Link, QUIC_CONFIGURATION, Link));
    }

    QuicLockRelease(&Registration->ConfigLock);

    QuicDispatchLockAcquire(&Registration->ConnectionLock);

    for (QUIC_LIST_ENTRY* Link = Registration->Connections.Flink;
        Link != &Registration->Connections;
        Link = Link->Flink) {
        QuicConnQueueTraceRundown(
            QUIC_CONTAINING_RECORD(Link, QUIC_CONNECTION, RegistrationLink));
    }

    QuicDispatchLockRelease(&Registration->ConnectionLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicRegistrationSettingsChanged(
    _Inout_ QUIC_REGISTRATION* Registration
    )
{
    QuicLockAcquire(&Registration->ConfigLock);

    for (QUIC_LIST_ENTRY* Link = Registration->Configurations.Flink;
        Link != &Registration->Configurations;
        Link = Link->Flink) {
        QuicConfigurationSettingsChanged(
            QUIC_CONTAINING_RECORD(Link, QUIC_CONFIGURATION, Link));
    }

    QuicLockRelease(&Registration->ConfigLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicRegistrationAcceptConnection(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ QUIC_CONNECTION* Connection
    )
{
    if (Registration->SplitPartitioning) {
        //
        // TODO - Constrain PartitionID to the same NUMA node?
        //
        Connection->PartitionID += QUIC_MAX_THROUGHPUT_PARTITION_OFFSET;
    }

    uint16_t Index =
        Registration->NoPartitioning ? 0 : QuicPartitionIdGetIndex(Connection->PartitionID);

    //
    // TODO - Look for other worker instead if the proposed worker is overloaded?
    //

    return !QuicWorkerIsOverloaded(&Registration->WorkerPool->Workers[Index]);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
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
    if (Param == QUIC_PARAM_REGISTRATION_CID_PREFIX) {
        if (BufferLength == 0) {
            if (Registration->CidPrefix != NULL) {
                QUIC_FREE(Registration->CidPrefix, QUIC_POOL_CIDPREFIX);
                Registration->CidPrefix = NULL;
            }
            Registration->CidPrefixLength = 0;
            return QUIC_STATUS_SUCCESS;
        }

        if (BufferLength > MSQUIC_CID_MAX_APP_PREFIX) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        if (BufferLength > Registration->CidPrefixLength) {
            uint8_t* NewCidPrefix = QUIC_ALLOC_NONPAGED(BufferLength, QUIC_POOL_CIDPREFIX);
            if (NewCidPrefix == NULL) {
                return QUIC_STATUS_OUT_OF_MEMORY;
            }
            QUIC_DBG_ASSERT(Registration->CidPrefix != NULL);
            QUIC_FREE(Registration->CidPrefix, QUIC_POOL_CIDPREFIX);
            Registration->CidPrefix = NewCidPrefix;
        }

        Registration->CidPrefixLength = (uint8_t)BufferLength;
        memcpy(Registration->CidPrefix, Buffer, BufferLength);

        return QUIC_STATUS_SUCCESS;
    }

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
    if (Param == QUIC_PARAM_REGISTRATION_CID_PREFIX) {

        if (*BufferLength < Registration->CidPrefixLength) {
            *BufferLength = Registration->CidPrefixLength;
            return QUIC_STATUS_BUFFER_TOO_SMALL;
        }

        if (Registration->CidPrefixLength > 0) {
            if (Buffer == NULL) {
                return QUIC_STATUS_INVALID_PARAMETER;
            }

            *BufferLength = Registration->CidPrefixLength;
            memcpy(Buffer, Registration->CidPrefix, Registration->CidPrefixLength);

        } else {
            *BufferLength = 0;
        }

        return QUIC_STATUS_SUCCESS;
    }

    return QUIC_STATUS_INVALID_PARAMETER;
}
