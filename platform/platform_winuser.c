/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Abstraction Layer.

Environment:

    Windows User Mode

--*/

#include "platform_internal.h"

#if defined(QUIC_LOGS_WPP) || defined(QUIC_LOGS_CLOG)
#include "platform_winuser.tmh"
#include <fastwppimpl.h>
#endif

uint64_t QuicPlatformPerfFreq;
uint64_t QuicTotalMemory;
QUIC_PLATFORM QuicPlatform = { NULL };

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatformSystemLoad(
    void
    )
{
#if defined(QUIC_LOGS_WPP) || defined(QUIC_LOGS_CLOG)
    FAST_WPP_INIT_TRACING(L"quic");
#endif

#ifdef QUIC_EVENTS_MANIFEST_ETW
    EventRegisterMicrosoft_Quic();
#endif

    (void)QueryPerformanceFrequency((LARGE_INTEGER*)&QuicPlatformPerfFreq);
    QuicPlatform.Heap = NULL;

    QuicTraceLogInfo("[ dll] Loaded");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatformSystemUnload(
    void
    )
{
    QuicTraceLogInfo("[ dll] Unloaded");
#ifdef QUIC_EVENTS_MANIFEST_ETW
    EventUnregisterMicrosoft_Quic();
#endif
#if defined(QUIC_LOGS_WPP) || defined(QUIC_LOGS_CLOG)
    FAST_WPP_CLEANUP();
#endif
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicPlatformInitialize(
    void
    )
{
    QUIC_STATUS Status;
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);

    QuicPlatform.Heap = HeapCreate(0, 0, 0);
    if (QuicPlatform.Heap == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    if (!GlobalMemoryStatusEx(&memInfo)) {
        DWORD Error = GetLastError();
        QuicTraceEvent(LibraryErrorStatus, Error, "GlobalMemoryStatusEx");
        Status = HRESULT_FROM_WIN32(Error);
        goto Error;
    }

    Status = QuicTlsLibraryInitialize();
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    QuicTotalMemory = memInfo.ullTotalPageFile;

    QuicTraceLogInfo("[ dll] Initialized (AvailMem = %llu bytes)", QuicTotalMemory);

Error:

    if (QUIC_FAILED(Status)) {
        if (QuicPlatform.Heap) {
            HeapDestroy(QuicPlatform.Heap);
            QuicPlatform.Heap = NULL;
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatformUninitialize(
    void
    )
{
    QuicTlsLibraryUninitialize();
    QUIC_DBG_ASSERT(QuicPlatform.Heap);
    HeapDestroy(QuicPlatform.Heap);
    QuicPlatform.Heap = NULL;
    QuicTraceLogInfo("[ dll] Uninitialized");
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPlatformLogAssert(
    _In_z_ const char* File,
    _In_ int Line,
    _In_z_ const char* Expr
    )
{
    QuicTraceEvent(LibraryAssert, (uint32_t)Line, File, Expr);
}

#ifdef QUIC_FUZZER
//
// When fuzzing we want predictable random numbers
// so that when injection / mutating traffic, variances in
// things like connection ID and random values do not
// invalidate the saved fuzzer inputs.
//
uint8_t QUIC_FUZZ_RND_IDX = 0;

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicRandom(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    )
{
    memset(Buffer, ++QUIC_FUZZ_RND_IDX, BufferLen);
    return 0;
}

#else

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicRandom(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    )
{
    //
    // Just use the system-preferred random number generator algorithm.
    //
    return (QUIC_STATUS)
        BCryptGenRandom(
            NULL,
            (uint8_t*)Buffer,
            BufferLen,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

#endif

_Ret_maybenull_
_Post_writable_byte_size_(ByteCount)
DECLSPEC_ALLOCATOR
void*
QuicAlloc(
    _In_ size_t ByteCount
    )
{
    QUIC_DBG_ASSERT(QuicPlatform.Heap);
    return HeapAlloc(QuicPlatform.Heap, 0, ByteCount);
}

void
QuicFree(
    __drv_freesMem(Mem) _Frees_ptr_opt_ void* Mem
    )
{
    (void)HeapFree(QuicPlatform.Heap, 0, Mem);
}

__declspec(noreturn)
void
KrmlExit(
    int n
    )
{
    UNREFERENCED_PARAMETER(n);
    QUIC_FRE_ASSERTMSG(FALSE, "miTLS hit a fatal error");
}

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

    switch(ControlCode) {
    case EVENT_CONTROL_CODE_ENABLE_PROVIDER:
    case EVENT_CONTROL_CODE_CAPTURE_STATE:
        if (CallbackContext == &MICROSOFT_MSQUIC_PROVIDER_Context) {
            QuicTraceRundown();
        }
        break;
    case EVENT_CONTROL_CODE_DISABLE_PROVIDER:
    default:
        break;
    }
}
#endif

#if defined(QUIC_LOGS_WPP) || defined(QUIC_LOGS_CLOG)
void
QuicForceWppInitCodeGeneration(
    void
    )
{
    //
    // This function exists to to make WPP generate the definitions for the
    // initialization and cleanup code, which happens only if there is direct
    // textual reference to the WPP_INIT_TRACING macro. It isn't called by
    // design.
    //
    WPP_INIT_TRACING(L"quic");
}
#endif
