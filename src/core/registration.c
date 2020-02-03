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

#ifdef QUIC_LOGS_WPP
#include "registration.tmh"
#endif

QUIC_DATAPATH_RECEIVE_CALLBACK MsQuicRecvCallback;

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicRegistrationAlloc(
    _In_opt_z_ const char* AppName,
    _In_ uint8_t ExecProfileType,
    _Outptr_ _At_(*NewRegistration, __drv_allocatesMem(Mem))
        HQUIC* NewRegistration
    )
{
    QUIC_STATUS Status;

    size_t AppNameLength = AppName == NULL ? 0 : strlen(AppName);

    QuicTraceEvent(ApiEnter,
        QUIC_TRACE_API_REGISTRATION_OPEN,
        NULL);

    QUIC_REGISTRATION* Registration =
        QUIC_ALLOC_NONPAGED(sizeof(QUIC_REGISTRATION) + AppNameLength + 1);
    if (Registration == NULL) {
        QuicTraceEvent(AllocFailure, "registration", sizeof(QUIC_REGISTRATION) + AppNameLength + 1);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Registration->Type = QUIC_HANDLE_TYPE_REGISTRATION;
    Registration->ClientContext = NULL;
    Registration->NoPartitioning = FALSE;
    Registration->ExecProfileType = ExecProfileType;
    Registration->CidPrefixLength = 0;
    Registration->CidPrefix = NULL;
    QuicLockInitialize(&Registration->Lock);
    QuicListInitializeHead(&Registration->Sessions);
    QuicRundownInitialize(&Registration->SecConfigRundown);
    if (AppNameLength != 0) {
        QuicCopyMemory(Registration->AppName, AppName, AppNameLength + 1);
    } else {
        Registration->AppName[0] = '\0';
    }

    uint16_t WorkerThreadFlags = 0;
    switch (Registration->ExecProfileType) {
    default:
    case QUIC_EXEC_PROF_TYPE_LOW_LATENCY:
        WorkerThreadFlags = QUIC_THREAD_FLAG_SET_IDEAL_PROC;
        break;
    case QUIC_EXEC_PROF_TYPE_MAX_THROUGHPUT:
        WorkerThreadFlags = QUIC_THREAD_FLAG_SET_IDEAL_PROC | QUIC_THREAD_FLAG_SET_AFFINITIZE;
        break;
    case QUIC_EXEC_PROF_TYPE_SCAVENGER:
        WorkerThreadFlags = 0;
        Registration->NoPartitioning = TRUE;
        break;
    case QUIC_EXEC_PROF_TYPE_REAL_TIME:
        WorkerThreadFlags =
            QUIC_THREAD_FLAG_SET_IDEAL_PROC |
            QUIC_THREAD_FLAG_SET_AFFINITIZE |
            QUIC_THREAD_FLAG_HIGH_PRIORITY;
        break;
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

    QuicTraceEvent(RegistrationCreated, Registration, Registration->AppName);

#ifdef QuicVerifierEnabledByAddr
    if (MsQuicLib.IsVerifying &&
        QuicVerifierEnabledByAddr(NewRegistration)) {
        Registration->IsVerifying = TRUE;
        QuicTraceLogInfo("[ reg][%p] Verifing enabled!", Registration);
    } else {
        Registration->IsVerifying = FALSE;
    }
#endif

    QuicLockAcquire(&MsQuicLib.Lock);
    QuicListInsertTail(&MsQuicLib.Registrations, &Registration->Link);
    QuicLockRelease(&MsQuicLib.Lock);

    *NewRegistration = (HQUIC)Registration;
    Registration = NULL;

Error:

    if (Registration != NULL) {
        QuicRundownUninitialize(&Registration->SecConfigRundown);
        QuicLockUninitialize(&Registration->Lock);
        QUIC_FREE(Registration);
    }

    QuicTraceEvent(ApiExitStatus, Status);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicRegistrationOpen(
    _In_opt_z_ const char* AppName,
    _Outptr_ _At_(*Registration, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Registration
    )
{
    if (Registration == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    return
        QuicRegistrationAlloc(
            AppName,
            QUIC_EXEC_PROF_TYPE_LOW_LATENCY,
            Registration);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicRegistrationOpenPriv(
    _In_opt_z_ const char* AppName,
    _In_opt_ const QUIC_EXEC_PROFILE* ExecProfile,
    _Outptr_ _At_(*Registration, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Registration
    )
{
    if (Registration == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    uint8_t ExecProfileType = QUIC_EXEC_PROF_TYPE_LOW_LATENCY;
    if (ExecProfile != NULL) {
        ExecProfileType = ExecProfile->Type;
    }

    return
        QuicRegistrationAlloc(
            AppName,
            ExecProfileType,
            Registration);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicRegistrationClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Handle
    )
{
    if (Handle == NULL) {
        return;
    }

    QUIC_TEL_ASSERT(Handle->Type == QUIC_HANDLE_TYPE_REGISTRATION);
    if (Handle->Type != QUIC_HANDLE_TYPE_REGISTRATION) {
        return;
    }

    QuicTraceEvent(ApiEnter,
        QUIC_TRACE_API_REGISTRATION_CLOSE,
        Handle);

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    QUIC_REGISTRATION* Registration = (QUIC_REGISTRATION*)Handle;

    QuicTraceEvent(RegistrationCleanup, Registration);

    //
    // If you hit this assert, you are trying to clean up a registration without
    // first cleaning up all the child sessions first.
    //
    QUIC_REG_VERIFY(Registration, QuicListIsEmpty(&Registration->Sessions));

    QuicLockAcquire(&MsQuicLib.Lock);
    QuicListEntryRemove(&Registration->Link);
    QuicLockRelease(&MsQuicLib.Lock);

    QuicWorkerPoolUninitialize(Registration->WorkerPool);
    QuicRundownReleaseAndWait(&Registration->SecConfigRundown);

    QuicRundownUninitialize(&Registration->SecConfigRundown);
    QuicLockUninitialize(&Registration->Lock);

    if (Registration->CidPrefix != NULL) {
        QUIC_FREE(Registration->CidPrefix);
    }

    QUIC_FREE(Registration);

    QuicTraceEvent(ApiExit);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicRegistrationTraceRundown(
    _In_ QUIC_REGISTRATION* Registration
    )
{
    QuicTraceEvent(RegistrationRundown, Registration, Registration->AppName);

    QuicLockAcquire(&Registration->Lock);

    for (QUIC_LIST_ENTRY* Link = Registration->Sessions.Flink;
        Link != &Registration->Sessions;
        Link = Link->Flink) {
        QuicSessionTraceRundown(
            QUIC_CONTAINING_RECORD(Link, QUIC_SESSION, Link));
    }

    QuicLockRelease(&Registration->Lock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicRegistrationSettingsChanged(
    _Inout_ QUIC_REGISTRATION* Registration
    )
{
    QuicLockAcquire(&Registration->Lock);

    for (QUIC_LIST_ENTRY* Link = Registration->Sessions.Flink;
        Link != &Registration->Sessions;
        Link = Link->Flink) {
        QuicSessionSettingsChanged(
            QUIC_CONTAINING_RECORD(Link, QUIC_SESSION, Link));
    }

    QuicLockRelease(&Registration->Lock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicSecConfigCreate(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_SEC_CONFIG_FLAGS Flags,
    _In_opt_ void* Certificate,
    _In_opt_z_ const char* Principal,
    _In_opt_ void* Context,
    _In_ _Pre_defensive_ QUIC_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    )
{
    QUIC_STATUS Status;

    QuicTraceEvent(ApiEnter,
        QUIC_TRACE_API_SEC_CONFIG_CREATE,
        Handle);

    if (Handle == NULL || Handle->Type != QUIC_HANDLE_TYPE_REGISTRATION ||
        CompletionHandler == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    QUIC_REGISTRATION* Registration = (QUIC_REGISTRATION*)Handle;
    Status =
        QuicTlsServerSecConfigCreate(
            &Registration->SecConfigRundown,
            Flags,
            Certificate,
            Principal,
            Context,
            CompletionHandler);

Exit:

    QuicTraceEvent(ApiExitStatus, Status);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicSecConfigDelete(
    _In_ _Pre_defensive_ QUIC_SEC_CONFIG* SecurityConfig
    )
{
    QuicTraceEvent(ApiEnter,
        QUIC_TRACE_API_SEC_CONFIG_DELETE,
        SecurityConfig);

    if (SecurityConfig != NULL) {
        QuicTlsSecConfigRelease(SecurityConfig);
    }

    QuicTraceEvent(ApiExit);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_CONNECTION_ACCEPT_RESULT
QuicRegistrationAcceptConnection(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ QUIC_CONNECTION* Connection
    )
{
    if (Registration->ExecProfileType == QUIC_EXEC_PROF_TYPE_MAX_THROUGHPUT) {
        //
        // TODO - Figure out how to check to see if hyper-threading was enabled first
        // TODO - Constrain ++PartitionID to the same NUMA node.
        //
        // When hyper-threading is enabled, better bulk throughput can sometimes
        // be gained by sharing the same physical core, but not the logical one.
        // The shared one is always one greater than the RSS core.
        //
        Connection->PartitionID++;
    }

    uint8_t Index =
        Registration->NoPartitioning ? 0 : QuicPartitionIdGetIndex(Connection->PartitionID);

    //
    // TODO - Look for other worker instead if the proposed worker is overloaded?
    //

    if (QuicWorkerIsOverloaded(&Registration->WorkerPool->Workers[Index])) {
        return QUIC_CONNECTION_REJECT_BUSY;
    } else {
        return QUIC_CONNECTION_ACCEPT;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicRegistrationQueueNewConnection(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ QUIC_CONNECTION* Connection
    )
{
    uint8_t Index =
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
    QUIC_STATUS Status;

    switch (Param) {
    case QUIC_PARAM_REGISTRATION_RETRY_MEMORY_PERCENT:

        if (BufferLength != sizeof(MsQuicLib.Settings.RetryMemoryLimit)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        MsQuicLib.Settings.RetryMemoryLimit = *(uint16_t*)Buffer;
        MsQuicLib.Settings.AppSet.RetryMemoryLimit = TRUE;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_REGISTRATION_CID_PREFIX:

        if (BufferLength == 0) {
            if (Registration->CidPrefix != NULL) {
                QUIC_FREE(Registration->CidPrefix);
                Registration->CidPrefix = NULL;
            }
            Registration->CidPrefixLength = 0;
            Status = QUIC_STATUS_SUCCESS;
            break;
        }

        if (BufferLength > QUIC_CID_MAX_APP_PREFIX) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (BufferLength > Registration->CidPrefixLength) {
            uint8_t* NewCidPrefix = QUIC_ALLOC_NONPAGED(BufferLength);
            if (NewCidPrefix == NULL) {
                Status = QUIC_STATUS_OUT_OF_MEMORY;
                break;
            }
            QUIC_DBG_ASSERT(Registration->CidPrefix != NULL);
            QUIC_FREE(Registration->CidPrefix);
            Registration->CidPrefix = NewCidPrefix;
        }

        Registration->CidPrefixLength = (uint8_t)BufferLength;
        memcpy(Registration->CidPrefix, Buffer, BufferLength);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_REGISTRATION_ENCRYPTION:

        if (BufferLength != sizeof(uint8_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        MsQuicLib.EncryptionDisabled = *(uint8_t*)Buffer == FALSE;

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
QuicRegistrationParamGet(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;

    switch (Param) {
    case QUIC_PARAM_REGISTRATION_RETRY_MEMORY_PERCENT:

        if (*BufferLength < sizeof(MsQuicLib.Settings.RetryMemoryLimit)) {
            *BufferLength = sizeof(MsQuicLib.Settings.RetryMemoryLimit);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(MsQuicLib.Settings.RetryMemoryLimit);
        *(uint16_t*)Buffer = MsQuicLib.Settings.RetryMemoryLimit;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_REGISTRATION_CID_PREFIX:

        if (*BufferLength < Registration->CidPrefixLength) {
            *BufferLength = Registration->CidPrefixLength;
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Registration->CidPrefixLength > 0) {
            if (Buffer == NULL) {
                Status = QUIC_STATUS_INVALID_PARAMETER;
                break;
            }

            *BufferLength = Registration->CidPrefixLength;
            memcpy(Buffer, Registration->CidPrefix, Registration->CidPrefixLength);

        } else {
            *BufferLength = 0;
        }

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_REGISTRATION_ENCRYPTION:

        if (*BufferLength < sizeof(uint8_t)) {
            *BufferLength = sizeof(uint8_t);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(uint8_t);
        *(uint8_t*)Buffer = !MsQuicLib.EncryptionDisabled;

        Status = QUIC_STATUS_SUCCESS;
        break;

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}
