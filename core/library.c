/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    General library functions

--*/

#include "precomp.h"

#ifdef QUIC_LOGS_WPP
#include "library.tmh"
#endif

#include "c:\source\msquic\bld\clog\library.c.clog"

QUIC_LIBRARY MsQuicLib = { 0 };

//
// Initializes all global variables.
//
INITCODE
_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryLoad(
    void
    )
{
    QuicLockInitialize(&MsQuicLib.Lock);
    QuicDispatchLockInitialize(&MsQuicLib.DatapathLock);
    QuicListInitializeHead(&MsQuicLib.Registrations);
    QuicListInitializeHead(&MsQuicLib.Bindings);
    MsQuicLib.Loaded = TRUE;
}

//
// Uninitializes global variables.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryUnload(
    void
    )
{
    QUIC_FRE_ASSERT(MsQuicLib.Loaded);
    QUIC_LIB_VERIFY(MsQuicLib.RefCount == 0);
    MsQuicLib.Loaded = FALSE;
    QuicDispatchLockUninitialize(&MsQuicLib.DatapathLock);
    QuicLockUninitialize(&MsQuicLib.Lock);
}

void
MsQuicCalculatePartitionMask(
    void
    )
{
    if (MsQuicLib.PartitionCount >= 128) {
        MsQuicLib.PartitionMask = 0xFF;
    } else if (MsQuicLib.PartitionCount >= 64) {
        MsQuicLib.PartitionMask = 0x7F;
    } else if (MsQuicLib.PartitionCount >= 32) {
        MsQuicLib.PartitionMask = 0x3F;
    } else if (MsQuicLib.PartitionCount >= 16) {
        MsQuicLib.PartitionMask = 0x1F;
    } else if (MsQuicLib.PartitionCount >= 8) {
        MsQuicLib.PartitionMask = 0x0F;
    } else if (MsQuicLib.PartitionCount >= 4) {
        MsQuicLib.PartitionMask = 0x07;
    } else if (MsQuicLib.PartitionCount >= 2) {
        MsQuicLib.PartitionMask = 0x03;
    } else if (MsQuicLib.PartitionCount >= 1) {
        MsQuicLib.PartitionMask = 0x01;
    } else {
        MsQuicLib.PartitionMask = 0;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_STORAGE_CHANGE_CALLBACK)
void
MsQuicLibraryReadSettings(
    _In_opt_ void* Context
    )
{
    QuicSettingsSetDefault(&MsQuicLib.Settings);
    if (MsQuicLib.Storage != NULL) {
        QuicSettingsLoad(&MsQuicLib.Settings, MsQuicLib.Storage);
    }

    QuicTraceLogInfo("[ lib] Settings %p Updated", &MsQuicLib.Settings);
    QuicSettingsDump(&MsQuicLib.Settings);

    BOOLEAN UpdateRegistrations = (Context != NULL);
    if (UpdateRegistrations) {
        QuicLockAcquire(&MsQuicLib.Lock);

        for (QUIC_LIST_ENTRY* Link = MsQuicLib.Registrations.Flink;
            Link != &MsQuicLib.Registrations;
            Link = Link->Flink) {
            QuicRegistrationSettingsChanged(
                QUIC_CONTAINING_RECORD(Link, QUIC_REGISTRATION, Link));
        }

        QuicLockRelease(&MsQuicLib.Lock);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
MsQuicLibraryInitialize(
    void
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN PlatformInitialized = FALSE;

    Status = QuicPlatformInitialize();
    if (QUIC_FAILED(Status)) {
        goto Error; // Cannot log anything if platform failed to initialize.
    }
    PlatformInitialized = TRUE;

    QUIC_DBG_ASSERT(US_TO_MS(QuicGetTimerResolution()) + 1 <= UINT8_MAX);
    MsQuicLib.TimerResolutionMs = (uint8_t)US_TO_MS(QuicGetTimerResolution()) + 1;

    QuicZeroMemory(&MsQuicLib.Settings, sizeof(MsQuicLib.Settings));
    Status =
        QuicStorageOpen(
            NULL,
            MsQuicLibraryReadSettings,
            (void*)TRUE, // Non-null indicates registrations should be updated
            &MsQuicLib.Storage);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning("[ lib] Failed to open global settings, 0x%x", Status);
        Status = QUIC_STATUS_SUCCESS; // Non-fatal, as the process may not have access
    }

    MsQuicLibraryReadSettings(NULL); // NULL means don't update registrations.

    uint8_t RawKey[QUIC_AEAD_AES_256_GCM_SIZE];
    QuicRandom(sizeof(RawKey), RawKey);
    Status =
        QuicKeyCreate(
            QUIC_AEAD_AES_256_GCM,
            RawKey,
            &MsQuicLib.StatelessRetryKey);
    if (QUIC_FAILED(Status)) {
        CLOG_TraceEvent(LibraryErrorStatusABC, "[ lib] ERROR, 0x%x, %s.", Status, "Create stateless retry key");
        goto Error;
    }

    //
    // TODO: Add support for CPU hot swap/add.
    //
    uint32_t MaxProcCount = QuicProcActiveCount();
    if (MaxProcCount > (uint32_t)MsQuicLib.Settings.MaxPartitionCount) {
        MaxProcCount = (uint32_t)MsQuicLib.Settings.MaxPartitionCount;
    }
    MsQuicLib.PartitionCount = (uint8_t)MaxProcCount;
    MsQuicCalculatePartitionMask();

    MsQuicLib.PerProc =
        QUIC_ALLOC_NONPAGED(MsQuicLib.PartitionCount * sizeof(QUIC_LIBRARY_PP));
    if (MsQuicLib.PerProc == NULL) {
        CLOG_TraceEvent(AllocFailure, "Allocation of '%s' failed. (%llu bytes)", "connection pools",
            MsQuicLib.PartitionCount * sizeof(QUIC_LIBRARY_PP));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    for (uint8_t i = 0; i < MsQuicLib.PartitionCount; ++i) {
        QuicPoolInitialize(
            FALSE,
            sizeof(QUIC_CONNECTION),
            &MsQuicLib.PerProc[i].ConnectionPool);
    }

    Status =
        QuicDataPathInitialize(
            sizeof(QUIC_RECV_PACKET),
            QuicBindingReceive,
            QuicBindingUnreachable,
            &MsQuicLib.Datapath);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(LibraryErrorStatus, Status, "QuicDataPathInitialize");
        goto Error;
    }

    CLOG_TraceEvent(LibraryInitialized, "[ lib] Initialized, PartitionCount=%u DatapathFeatures=%u",
        MsQuicLib.PartitionCount,
        QuicDataPathGetSupportedFeatures(MsQuicLib.Datapath));

#ifdef QuicVerifierEnabled
    uint32_t Flags;
    MsQuicLib.IsVerifying = QuicVerifierEnabled(Flags);
    if (MsQuicLib.IsVerifying) {
#ifdef QuicVerifierEnabledByAddr
        QuicTraceLogInfo("[ lib] Verifing enabled, per-registration!");
#else
        QuicTraceLogInfo("[ lib] Verifing enabled for all!");
#endif
    }
#endif

Error:

    if (QUIC_FAILED(Status)) {
        if (MsQuicLib.StatelessRetryKey != NULL) {
            QuicKeyFree(MsQuicLib.StatelessRetryKey);
            MsQuicLib.StatelessRetryKey = NULL;
        }
        if (MsQuicLib.PerProc != NULL) {
            for (uint8_t i = 0; i < MsQuicLib.PartitionCount; ++i) {
                QuicPoolUninitialize(&MsQuicLib.PerProc[i].ConnectionPool);
            }
            QUIC_FREE(MsQuicLib.PerProc);
            MsQuicLib.PerProc = NULL;
        }
        if (MsQuicLib.Storage != NULL) {
            QuicStorageClose(MsQuicLib.Storage);
            MsQuicLib.Storage = NULL;
        }
        if (PlatformInitialized) {
            QuicPlatformUninitialize();
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryUninitialize(
    void
    )
{
    //
    // If you hit this assert, MsQuic API is trying to be unloaded without
    // first closing all registrations.
    //
    QUIC_TEL_ASSERT(QuicListIsEmpty(&MsQuicLib.Registrations));

    if (MsQuicLib.Storage != NULL) {
        QuicStorageClose(MsQuicLib.Storage);
        MsQuicLib.Storage = NULL;
    }

    //
    // The library's worker pool for processing half-opened connections
    // needs to be cleaned up first, as it's the last thing that can be
    // holding on to connection objects.
    //
    if (MsQuicLib.WorkerPool != NULL) {
        QuicWorkerPoolUninitialize(MsQuicLib.WorkerPool);
        MsQuicLib.WorkerPool = NULL;
    }

#if QUIC_TEST_MODE
    //
    // If you hit this assert, MsQuic API is trying to be unloaded without
    // first cleaning up all connections.
    //
    QUIC_TEL_ASSERT(MsQuicLib.ConnectionCount == 0);
#endif

    //
    // If you hit this assert, MsQuic API is trying to be unloaded without
    // first being cleaned up all listeners and connections.
    //
    QUIC_TEL_ASSERT(QuicListIsEmpty(&MsQuicLib.Bindings));

    for (uint8_t i = 0; i < MsQuicLib.PartitionCount; ++i) {
        QuicPoolUninitialize(&MsQuicLib.PerProc[i].ConnectionPool);
    }
    QUIC_FREE(MsQuicLib.PerProc);
    MsQuicLib.PerProc = NULL;

    QuicKeyFree(MsQuicLib.StatelessRetryKey);
    MsQuicLib.StatelessRetryKey = NULL;

    QuicDataPathUninitialize(MsQuicLib.Datapath);
    MsQuicLib.Datapath = NULL;

    QuicTraceEvent(LibraryUninitialized);

    QuicPlatformUninitialize();
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
MsQuicAddRef(
    void
    )
{
    //
    // If you hit this assert, you are trying to call MsQuic API without
    // actually loading/starting the library/driver.
    //
    QUIC_TEL_ASSERT(MsQuicLib.Loaded);
    if (!MsQuicLib.Loaded) {
        return QUIC_STATUS_INVALID_STATE;
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    QuicLockAcquire(&MsQuicLib.Lock);

    //
    // Increment global ref count, and if this is the first ref, initialize all
    // the global library state.
    //
    if (++MsQuicLib.RefCount == 1) {
        Status = MsQuicLibraryInitialize();
        if (QUIC_FAILED(Status)) {
            MsQuicLib.RefCount--;
            goto Error;
        }
    }

    QuicTraceEvent(LibraryAddRef);

Error:

    QuicLockRelease(&MsQuicLib.Lock);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicRelease(
    void
    )
{
    QuicLockAcquire(&MsQuicLib.Lock);

    //
    // Decrement global ref count and uninitialize the library if this is the
    // last ref.
    //

    QUIC_FRE_ASSERT(MsQuicLib.RefCount > 0);
    QuicTraceEvent(LibraryRelease);

    if (--MsQuicLib.RefCount == 0) {
        MsQuicLibraryUninitialize();
    }

    QuicLockRelease(&MsQuicLib.Lock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QUIC_API
MsQuicSetContext(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_opt_ void* Context
    )
{
    if (Handle != NULL) {
        Handle->ClientContext = Context;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void*
QUIC_API
MsQuicGetContext(
    _In_ _Pre_defensive_ HQUIC Handle
    )
{
    return Handle == NULL ? NULL : Handle->ClientContext;
}

#pragma warning(disable:28023) // The function being assigned or passed should have a _Function_class_ annotation

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QUIC_API
MsQuicSetCallbackHandler(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ void* Handler,
    _In_opt_ void* Context
    )
{
    if (Handle == NULL) {
        return;
    }

    switch (Handle->Type) {

    case QUIC_HANDLE_TYPE_LISTENER:
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        ((QUIC_LISTENER*)Handle)->ClientCallbackHandler =
            (QUIC_LISTENER_CALLBACK_HANDLER)Handler;
        break;

    case QUIC_HANDLE_TYPE_CLIENT:
    case QUIC_HANDLE_TYPE_CHILD:
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        ((QUIC_CONNECTION*)Handle)->ClientCallbackHandler =
            (QUIC_CONNECTION_CALLBACK_HANDLER)Handler;
        break;

    case QUIC_HANDLE_TYPE_STREAM:
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        ((QUIC_STREAM*)Handle)->ClientCallbackHandler =
            (QUIC_STREAM_CALLBACK_HANDLER)Handler;
        break;

    default:
        return;
    }

    Handle->ClientContext = Context;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibrarySetParam(
    _In_ HQUIC Handle,
    _In_ QUIC_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    QUIC_STATUS Status;
    QUIC_REGISTRATION* Registration;
    QUIC_SESSION* Session;
    QUIC_LISTENER* Listener;
    QUIC_CONNECTION* Connection;
    QUIC_STREAM* Stream;

    switch (Handle->Type) {

    case QUIC_HANDLE_TYPE_REGISTRATION:
        Stream = NULL;
        Connection = NULL;
        Listener = NULL;
        Session = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Registration = (QUIC_REGISTRATION*)Handle;
        break;

    case QUIC_HANDLE_TYPE_SESSION:
        Stream = NULL;
        Connection = NULL;
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Session = (QUIC_SESSION*)Handle;
        Registration = Session->Registration;
        break;

    case QUIC_HANDLE_TYPE_LISTENER:
        Stream = NULL;
        Connection = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Listener = (QUIC_LISTENER*)Handle;
        Session = Listener->Session;
        Registration = Session->Registration;
        break;

    case QUIC_HANDLE_TYPE_CLIENT:
    case QUIC_HANDLE_TYPE_CHILD:
        Stream = NULL;
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
        Session = Connection->Session;
        QUIC_DBG_ASSERT(Session != NULL);
        Registration = Session->Registration;
        break;

    case QUIC_HANDLE_TYPE_STREAM:
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Stream = (QUIC_STREAM*)Handle;
        Connection = Stream->Connection;
        Session = Connection->Session;
        QUIC_DBG_ASSERT(Session != NULL);
        Registration = Session->Registration;
        break;

    default:
        QUIC_TEL_ASSERT(FALSE);
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    switch (Level)
    {
    case QUIC_PARAM_LEVEL_REGISTRATION:
        if (Registration == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicRegistrationParamSet(Registration, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_SESSION:
        if (Session == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicSessionParamSet(Session, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_LISTENER:
        if (Listener == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicListenerParamSet(Listener, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_CONNECTION:
        if (Connection == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicConnParamSet(Connection, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_TLS:
        if (Connection == NULL || Connection->Crypto.TLS == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicTlsParamSet(Connection->Crypto.TLS, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_STREAM:
        if (Stream == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicStreamParamSet(Stream, Param, BufferLength, Buffer);
        }
        break;

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

Error:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryGetParam(
    _In_ HQUIC Handle,
    _In_ QUIC_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;
    QUIC_REGISTRATION* Registration;
    QUIC_SESSION* Session;
    QUIC_LISTENER* Listener;
    QUIC_CONNECTION* Connection;
    QUIC_STREAM* Stream;

    QUIC_DBG_ASSERT(BufferLength);

    switch (Handle->Type) {

    case QUIC_HANDLE_TYPE_REGISTRATION:
        Stream = NULL;
        Connection = NULL;
        Listener = NULL;
        Session = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Registration = (QUIC_REGISTRATION*)Handle;
        break;

    case QUIC_HANDLE_TYPE_SESSION:
        Stream = NULL;
        Connection = NULL;
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Session = (QUIC_SESSION*)Handle;
        Registration = Session->Registration;
        break;

    case QUIC_HANDLE_TYPE_LISTENER:
        Stream = NULL;
        Connection = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Listener = (QUIC_LISTENER*)Handle;
        Session = Listener->Session;
        Registration = Session->Registration;
        break;

    case QUIC_HANDLE_TYPE_CLIENT:
    case QUIC_HANDLE_TYPE_CHILD:
        Stream = NULL;
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
        Session = Connection->Session;
        QUIC_TEL_ASSERT(Session != NULL);
        Registration = Session->Registration;
        break;

    case QUIC_HANDLE_TYPE_STREAM:
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Stream = (QUIC_STREAM*)Handle;
        Connection = Stream->Connection;
        Session = Connection->Session;
        QUIC_TEL_ASSERT(Session != NULL);
        Registration = Session->Registration;
        break;

    default:
        QUIC_TEL_ASSERT(FALSE);
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    switch (Level)
    {
    case QUIC_PARAM_LEVEL_REGISTRATION:
        if (Registration == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicRegistrationParamGet(Registration, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_SESSION:
        if (Session == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicSessionParamGet(Session, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_LISTENER:
        if (Listener == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicListenerParamGet(Listener, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_CONNECTION:
        if (Connection == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicConnParamGet(Connection, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_TLS:
        if (Connection == NULL || Connection->Crypto.TLS == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicTlsParamGet(Connection->Crypto.TLS, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_STREAM:
        if (Stream == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicStreamParamGet(Stream, Param, BufferLength, Buffer);
        }
        break;

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

Error:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Pre_defensive_
QUIC_STATUS
QUIC_API
MsQuicOpen(
    _In_ uint32_t ApiVersion,
    _Out_ void** QuicApi     // struct QUIC_API_*
    )
{
    QUIC_STATUS Status;

    if (QuicApi == NULL) {
        QuicTraceLogVerbose("[ api] MsQuicOpen, NULL");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    QuicTraceLogVerbose("[ api] MsQuicOpen, %u", ApiVersion);

    if ((ApiVersion == 0 || ApiVersion > QUIC_API_VERSION_1) &&
        ApiVersion != QUIC_API_VERSION_PRIVATE) {
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    Status = MsQuicAddRef();
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    switch (ApiVersion) {
    case QUIC_API_VERSION_1: {
        QUIC_API_V1* ApiV1 = QUIC_ALLOC_NONPAGED(sizeof(QUIC_API_V1));
        if (ApiV1 == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }

        *QuicApi = ApiV1;

        ApiV1->Version = QUIC_API_VERSION_1;

        ApiV1->SetContext = MsQuicSetContext;
        ApiV1->GetContext = MsQuicGetContext;
        ApiV1->SetCallbackHandler = MsQuicSetCallbackHandler;

        ApiV1->SetParam = MsQuicSetParam;
        ApiV1->GetParam = MsQuicGetParam;

        ApiV1->RegistrationOpen = MsQuicRegistrationOpen;
        ApiV1->RegistrationClose = MsQuicRegistrationClose;

        ApiV1->SecConfigCreate = MsQuicSecConfigCreate;
        ApiV1->SecConfigDelete = MsQuicSecConfigDelete;

        ApiV1->SessionOpen = MsQuicSessionOpen;
        ApiV1->SessionClose = MsQuicSessionClose;
        ApiV1->SessionShutdown = MsQuicSessionShutdown;

        ApiV1->ListenerOpen = MsQuicListenerOpen;
        ApiV1->ListenerClose = MsQuicListenerClose;
        ApiV1->ListenerStart = MsQuicListenerStart;
        ApiV1->ListenerStop = MsQuicListenerStop;

        ApiV1->ConnectionOpen = MsQuicConnectionOpen;
        ApiV1->ConnectionClose = MsQuicConnectionClose;
        ApiV1->ConnectionShutdown = MsQuicConnectionShutdown;
        ApiV1->ConnectionStart = MsQuicConnectionStart;

        ApiV1->StreamOpen = MsQuicStreamOpen;
        ApiV1->StreamClose = MsQuicStreamClose;
        ApiV1->StreamShutdown = MsQuicStreamShutdown;
        ApiV1->StreamStart = MsQuicStreamStart;
        ApiV1->StreamSend = MsQuicStreamSend;
        ApiV1->StreamReceiveComplete = MsQuicStreamReceiveComplete;
        ApiV1->StreamReceiveSetEnabled = MsQuicStreamReceiveSetEnabled;
        break;
    }
    case QUIC_API_VERSION_PRIVATE: {
        QUIC_API_PRIVATE* ApiPriv = QUIC_ALLOC_NONPAGED(sizeof(QUIC_API_PRIVATE));
        if (ApiPriv == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }

        *QuicApi = ApiPriv;

        ApiPriv->Version = QUIC_API_VERSION_PRIVATE;

        ApiPriv->SetContext = MsQuicSetContext;
        ApiPriv->GetContext = MsQuicGetContext;
        ApiPriv->SetCallbackHandler = MsQuicSetCallbackHandler;

        ApiPriv->SetParam = MsQuicSetParam;
        ApiPriv->GetParam = MsQuicGetParam;

        ApiPriv->RegistrationOpen = MsQuicRegistrationOpenPriv;
        ApiPriv->RegistrationClose = MsQuicRegistrationClose;

        ApiPriv->SecConfigCreate = MsQuicSecConfigCreate;
        ApiPriv->SecConfigDelete = QuicTlsSecConfigRelease;

        ApiPriv->SessionOpen = MsQuicSessionOpen;
        ApiPriv->SessionClose = MsQuicSessionClose;
        ApiPriv->SessionShutdown = MsQuicSessionShutdown;

        ApiPriv->ListenerOpen = MsQuicListenerOpen;
        ApiPriv->ListenerClose = MsQuicListenerClose;
        ApiPriv->ListenerStart = MsQuicListenerStart;
        ApiPriv->ListenerStop = MsQuicListenerStop;

        ApiPriv->ConnectionOpen = MsQuicConnectionOpen;
        ApiPriv->ConnectionClose = MsQuicConnectionClose;
        ApiPriv->ConnectionShutdown = MsQuicConnectionShutdown;
        ApiPriv->ConnectionStart = MsQuicConnectionStart;

        ApiPriv->StreamOpen = MsQuicStreamOpen;
        ApiPriv->StreamClose = MsQuicStreamClose;
        ApiPriv->StreamShutdown = MsQuicStreamShutdown;
        ApiPriv->StreamStart = MsQuicStreamStart;
        ApiPriv->StreamSend = MsQuicStreamSend;
        ApiPriv->StreamReceiveComplete = MsQuicStreamReceiveComplete;
        ApiPriv->StreamReceiveSetEnabled = MsQuicStreamReceiveSetEnabled;
        break;
    }
    default: {
        QUIC_FRE_ASSERT(FALSE); // Should be unreachable code.
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Error;
    }
    }

Error:

    if (QUIC_FAILED(Status)) {
        MsQuicRelease();
    }

Exit:

    QuicTraceLogVerbose("[ api] MsQuicOpen, status=0x%x", Status);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Pre_defensive_
void
QUIC_API
MsQuicClose(
    _In_ const void* QuicApi
    )
{
    if (QuicApi != NULL) {
        QuicTraceLogVerbose("[ api] MsQuicClose");
        QUIC_FREE(QuicApi);
        MsQuicRelease();
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_BINDING*
QuicLibraryLookupBinding(
#ifdef QUIC_COMPARTMENT_ID
    _In_ QUIC_COMPARTMENT_ID CompartmentId,
#endif
    _In_ const QUIC_ADDR * LocalAddress,
    _In_opt_ const QUIC_ADDR * RemoteAddress
    )
{
    for (QUIC_LIST_ENTRY* Link = MsQuicLib.Bindings.Flink;
        Link != &MsQuicLib.Bindings;
        Link = Link->Flink) {

        QUIC_BINDING* Binding =
            QUIC_CONTAINING_RECORD(Link, QUIC_BINDING, Link);

#ifdef QUIC_COMPARTMENT_ID
        if (CompartmentId != Binding->CompartmentId) {
            continue;
        }
#endif

        QUIC_ADDR BindingLocalAddr;
        QuicDataPathBindingGetLocalAddress(Binding->DatapathBinding, &BindingLocalAddr);

        if (!QuicAddrCompare(LocalAddress, &BindingLocalAddr)) {
            continue;
        }

        if (Binding->Connected) {
            if (RemoteAddress == NULL) {
                continue;
            }

            QUIC_ADDR BindingRemoteAddr;
            QuicDataPathBindingGetRemoteAddress(Binding->DatapathBinding, &BindingRemoteAddr);
            if (!QuicAddrCompare(RemoteAddress, &BindingRemoteAddr)) {
                continue;
            }

        } else  if (RemoteAddress != NULL) {
            continue;
        }

        return Binding;
    }

    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryGetBinding(
    _In_ QUIC_SESSION* Session,
    _In_ BOOLEAN ShareBinding,
    _In_opt_ const QUIC_ADDR * LocalAddress,
    _In_opt_ const QUIC_ADDR * RemoteAddress,
    _Out_ QUIC_BINDING** NewBinding
    )
{
    QUIC_STATUS Status = QUIC_STATUS_NOT_FOUND;
    QUIC_BINDING* Binding;
    QUIC_ADDR NewLocalAddress;

    //
    // First check to see if a binding already exists that matches the
    // requested addresses.
    //

    if (LocalAddress == NULL) {
        //
        // No specified local address, so we just always create a new binding.
        //
        goto NewBinding;
    }

    QuicDispatchLockAcquire(&MsQuicLib.DatapathLock);

    Binding =
        QuicLibraryLookupBinding(
#ifdef QUIC_COMPARTMENT_ID
            Session->CompartmentId,
#endif
            LocalAddress,
            RemoteAddress);
    if (Binding != NULL) {
        if (!ShareBinding || Binding->Exclusive) {
            //
            // The binding does already exist, but its owner has exclusive
            // ownership of the binding.
            //
            Status = QUIC_STATUS_INVALID_STATE;
        } else {
            //
            // Match found and its owner is willing to share.
            //
            QUIC_DBG_ASSERT(Binding->RefCount > 0);
            Binding->RefCount++;
            *NewBinding = Binding;
            Status = QUIC_STATUS_SUCCESS;
        }
    }

    QuicDispatchLockRelease(&MsQuicLib.DatapathLock);

    if (Status != QUIC_STATUS_NOT_FOUND) {
        goto Exit;
    }

NewBinding:

    //
    // Create a new binding since there wasn't a match.
    //

    Status =
        QuicBindingInitialize(
#ifdef QUIC_COMPARTMENT_ID
            Session->CompartmentId,
#endif
            ShareBinding,
            LocalAddress,
            RemoteAddress,
            NewBinding);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    QuicDataPathBindingGetLocalAddress((*NewBinding)->DatapathBinding, &NewLocalAddress);

    QuicDispatchLockAcquire(&MsQuicLib.DatapathLock);

    //
    // Now that we created the binding, we need to insert it into the list of
    // all bindings. But we need to make sure another thread didn't race this
    // one and already create the binding.
    //

#if 0
    Binding = QuicLibraryLookupBinding(&NewLocalAddress, RemoteAddress);
#else
    //
    // Don't allow multiple sockets on the same local tuple currently. So just
    // do collision detection based on local tuple.
    //
    Binding =
        QuicLibraryLookupBinding(
#ifdef QUIC_COMPARTMENT_ID
            Session->CompartmentId,
#endif
            &NewLocalAddress,
            NULL);
#endif
    if (Binding != NULL) {
        if (!Binding->Exclusive) {
            //
            // Another thread got the binding first, but it's not exclusive.
            //
            QUIC_DBG_ASSERT(Binding->RefCount > 0);
            Binding->RefCount++;
        }
    } else {
        //
        // No other thread beat us, insert this binding into the list.
        //
        QuicListInsertTail(&MsQuicLib.Bindings, &(*NewBinding)->Link);
    }

    QuicDispatchLockRelease(&MsQuicLib.DatapathLock);

    if (Binding != NULL) {
        if (Binding->Exclusive) {
            Status = QUIC_STATUS_INVALID_STATE;
        } else {
            (*NewBinding)->RefCount--;
            QuicBindingUninitialize(*NewBinding);
            *NewBinding = Binding;
            Status = QUIC_STATUS_SUCCESS;
        }
    }

Exit:

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLibraryTryAddRefBinding(
    _In_ QUIC_BINDING* Binding
    )
{
    BOOLEAN Success = FALSE;

    QuicDispatchLockAcquire(&MsQuicLib.DatapathLock);
    if (Binding->RefCount > 0) {
        Binding->RefCount++;
        Success = TRUE;
    }
    QuicDispatchLockRelease(&MsQuicLib.DatapathLock);

    return Success;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLibraryReleaseBinding(
    _In_ QUIC_BINDING* Binding
    )
{
    BOOLEAN Uninitialize = FALSE;

    QUIC_PASSIVE_CODE();

    QuicDispatchLockAcquire(&MsQuicLib.DatapathLock);
    QUIC_DBG_ASSERT(Binding->RefCount > 0);
    if (--Binding->RefCount == 0) {
        QuicListEntryRemove(&Binding->Link);
        Uninitialize = TRUE;
    }
    QuicDispatchLockRelease(&MsQuicLib.DatapathLock);

    if (Uninitialize) {
        QuicBindingUninitialize(Binding);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicLibraryOnListenerRegistered(
    _In_ QUIC_LISTENER* Listener
    )
{
    BOOLEAN Success = TRUE;

    UNREFERENCED_PARAMETER(Listener);

    QuicLockAcquire(&MsQuicLib.Lock);

    if (MsQuicLib.WorkerPool == NULL) {
        //
        // Make sure the handshake worker threads are initialized.
        //
        QuicTraceEvent(LibraryWorkerPoolInit);
        if (QUIC_FAILED(
            QuicWorkerPoolInitialize(
                NULL,
                0,
                max(1, MsQuicLib.PartitionCount / 4),
                &MsQuicLib.WorkerPool))) {
            Success = FALSE;
        }
    }

    QuicLockRelease(&MsQuicLib.Lock);

    return Success;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_WORKER*
QuicLibraryGetWorker(
    void
    )
{
    QUIC_DBG_ASSERT(MsQuicLib.WorkerPool != NULL);
    return
        &MsQuicLib.WorkerPool->Workers[
            MsQuicLib.NextWorkerIndex++ % MsQuicLib.WorkerPool->WorkerCount];
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTraceRundown(
    void
    )
{
    if (!MsQuicLib.Loaded) {
        return;
    }

    QuicLockAcquire(&MsQuicLib.Lock);

    if (MsQuicLib.RefCount > 0) {
        QuicTraceEvent(LibraryRundown,
            MsQuicLib.PartitionCount,
            QuicDataPathGetSupportedFeatures(MsQuicLib.Datapath));

        for (QUIC_LIST_ENTRY* Link = MsQuicLib.Registrations.Flink;
            Link != &MsQuicLib.Registrations;
            Link = Link->Flink) {
            QuicRegistrationTraceRundown(
                QUIC_CONTAINING_RECORD(Link, QUIC_REGISTRATION, Link));
        }

        QuicDispatchLockAcquire(&MsQuicLib.DatapathLock);
        for (QUIC_LIST_ENTRY* Link = MsQuicLib.Bindings.Flink;
            Link != &MsQuicLib.Bindings;
            Link = Link->Flink) {
            QuicBindingTraceRundown(
                QUIC_CONTAINING_RECORD(Link, QUIC_BINDING, Link));
        }
        QuicDispatchLockRelease(&MsQuicLib.DatapathLock);
    }

    QuicLockRelease(&MsQuicLib.Lock);
}
