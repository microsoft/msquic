/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Abstraction Layer.

Environment:

    Windows Kernel Mode

--*/

#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "platform_winkernel.c.clog.h"
#endif

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation                          = 0
} SYSTEM_INFORMATION_CLASS;

NTSYSAPI // Copied from zwapi.h.
NTSTATUS
NTAPI
ZwQuerySystemInformation (
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __out_bcount_part_opt(SystemInformationLength, *ReturnLength) PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );

typedef struct _SYSTEM_BASIC_INFORMATION {
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;

    //
    // WARNING: The following fields are 32-bit and may get
    // capped to MAXULONG on systems with a lot of RAM!
    //
    // Use SYSTEM_PHYSICAL_MEMORY_INFORMATION instead.
    //

    ULONG NumberOfPhysicalPages;      // Deprecated, do not use.
    ULONG LowestPhysicalPageNumber;   // Deprecated, do not use.
    ULONG HighestPhysicalPageNumber;  // Deprecated, do not use.

    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;


uint64_t CxPlatPerfFreq;
uint64_t CxPlatTotalMemory;
CX_PLATFORM CxPlatform = { NULL };
QUIC_TRACE_RUNDOWN_CALLBACK* QuicTraceRundownCallback;

PAGEDX
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSystemLoad(
    void
    )
{
    PAGED_CODE();

#ifdef QUIC_EVENTS_MANIFEST_ETW
    EventRegisterMicrosoft_Quic();
#endif

    (VOID)KeQueryPerformanceCounter((LARGE_INTEGER*)&CxPlatPerfFreq);
    CxPlatform.RngAlgorithm = NULL;

#ifdef DEBUG
    CxPlatform.AllocFailDenominator = 0;
    CxPlatform.AllocCounter = 0;
#endif

    QuicTraceLogInfo(
        WindowsKernelLoaded,
        "[ sys] Loaded");
}

PAGEDX
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSystemUnload(
    void
    )
{
    PAGED_CODE();

    QuicTraceLogInfo(
        WindowsKernelUnloaded,
        "[ sys] Unloaded");

#ifdef QUIC_EVENTS_MANIFEST_ETW
    EventUnregisterMicrosoft_Quic();
#endif
}

PAGEDX
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatInitialize(
    void
    )
{
    SYSTEM_BASIC_INFORMATION Sbi;

    PAGED_CODE();

    QUIC_STATUS Status =
        BCryptOpenAlgorithmProvider(
            &CxPlatform.RngAlgorithm,
            BCRYPT_RNG_ALGORITHM,
            NULL,
            BCRYPT_PROV_DISPATCH);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptOpenAlgorithmProvider (RNG)");
        goto Error;
    }
    CXPLAT_DBG_ASSERT(CxPlatform.RngAlgorithm != NULL);

    Status =
        ZwQuerySystemInformation(
            SystemBasicInformation, &Sbi, sizeof(Sbi), NULL);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "ZwQuerySystemInformation(SystemBasicInformation)");
        goto Error;
    }

    Status = CxPlatCryptInitialize();
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatCryptInitialize");
        goto Error;
    }

    //
    // TODO - Apparently this can be increased via hot memory add. Figure out
    // how to know when to update this value.
    //
    CxPlatTotalMemory = (uint64_t)Sbi.NumberOfPhysicalPages * (uint64_t)Sbi.PageSize;

    QuicTraceLogInfo(
        WindowsKernelInitialized,
        "[ sys] Initialized (PageSize = %u bytes; AvailMem = %llu bytes)",
        Sbi.PageSize,
        CxPlatTotalMemory);

Error:

    if (QUIC_FAILED(Status)) {
        if (CxPlatform.RngAlgorithm != NULL) {
            BCryptCloseAlgorithmProvider(CxPlatform.RngAlgorithm, 0);
            CxPlatform.RngAlgorithm = NULL;
        }
    }

    return Status;
}

PAGEDX
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatUninitialize(
    void
    )
{
    PAGED_CODE();
    CxPlatCryptUninitialize();
    BCryptCloseAlgorithmProvider(CxPlatform.RngAlgorithm, 0);
    CxPlatform.RngAlgorithm = NULL;
    QuicTraceLogInfo(
        WindowsKernelUninitialized,
        "[ sys] Uninitialized");
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatLogAssert(
    _In_z_ const char* File,
    _In_ int Line,
    _In_z_ const char* Expr
    )
{
    UNREFERENCED_PARAMETER(File);
    UNREFERENCED_PARAMETER(Line);
    UNREFERENCED_PARAMETER(Expr);
    QuicTraceEvent(
        LibraryAssert,
        "[ lib] ASSERT, %u:%s - %s.",
        (uint32_t)Line,
        File,
        Expr);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatRandom(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    )
{
    //
    // Use the algorithm we initialized for DISPATCH_LEVEL usage.
    //
    CXPLAT_DBG_ASSERT(CxPlatform.RngAlgorithm != NULL);
    return (QUIC_STATUS)
        BCryptGenRandom(
            CxPlatform.RngAlgorithm,
            (uint8_t*)Buffer,
            BufferLen,
            0);
}

#ifdef DEBUG

void
CxPlatSetAllocFailDenominator(
    _In_ int32_t Value
    )
{
    CxPlatform.AllocFailDenominator = Value;
    CxPlatform.AllocCounter = 0;
}

int32_t
CxPlatGetAllocFailDenominator(
    )
{
    return CxPlatform.AllocFailDenominator;
}

#endif

#ifdef QUIC_EVENTS_MANIFEST_ETW

_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_same_
void
NTAPI
QuicEtwCallback(
    _In_ LPCGUID SourceId,
    _In_ ULONG ControlCode,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _Inout_opt_ PVOID CallbackContext
    )
{
    UNREFERENCED_PARAMETER(SourceId);
    UNREFERENCED_PARAMETER(Level);
    UNREFERENCED_PARAMETER(MatchAnyKeyword);
    UNREFERENCED_PARAMETER(MatchAllKeyword);
    UNREFERENCED_PARAMETER(FilterData);

    if (!QuicTraceRundownCallback) {
        return;
    }

    switch(ControlCode) {
    case EVENT_CONTROL_CODE_ENABLE_PROVIDER:
    case EVENT_CONTROL_CODE_CAPTURE_STATE:
        if (CallbackContext == &MICROSOFT_MSQUIC_PROVIDER_Context) {
            QuicTraceRundownCallback();
        }
        break;
    case EVENT_CONTROL_CODE_DISABLE_PROVIDER:
    default:
        break;
    }
}

#endif
