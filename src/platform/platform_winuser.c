/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Abstraction Layer.

Environment:

    Windows User Mode

--*/

#include "platform_internal.h"
#include "platform_winuser.c.clog.h"

#if defined(QUIC_EVENTS_TRACELOGGING)
 // {6A7F6746-617F-40A3-8EAC-B84C022058FB}
TRACELOGGING_DEFINE_PROVIDER(
    clog_hTrace,
    "MSQuic",
    (0x6a7f6746, 0x617f, 0x40a3, 0x8e, 0xac, 0xb8, 0x4c, 0x2, 0x20, 0x58, 0xfb ));
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
    EventRegisterMicrosoft_Quic_ETW();
    TraceLoggingRegister(clog_hTrace);

    (void)QueryPerformanceFrequency((LARGE_INTEGER*)&QuicPlatformPerfFreq);
    QuicPlatform.Heap = NULL;

    QuicTraceLogInfo(FN_platform_winuser8e387020259f41ef110ccaeebe910f40, "[ dll] Loaded");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatformSystemUnload(
    void
    )
{
    QuicTraceLogInfo(FN_platform_winuser0c22020f4491112ca1f62af9913bb8bd, "[ dll] Unloaded");
    EventUnregisterMicrosoft_Quic_ETW();
    TraceLoggingUnregister(clog_hTrace);
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
        QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %d, %s.", Error, "GlobalMemoryStatusEx");
        Status = HRESULT_FROM_WIN32(Error);
        goto Error;
    }

    Status = QuicTlsLibraryInitialize();
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    QuicTotalMemory = memInfo.ullTotalPageFile;

    QuicTraceLogInfo(FN_platform_winuser73ea831dacee5fd83da7d83c77bdbcdb, "[ dll] Initialized (AvailMem = %llu bytes)", QuicTotalMemory);

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
    QuicTraceLogInfo(FN_platform_winuserd673a9c82917e2cfa2aeed8357e33ee9, "[ dll] Uninitialized");
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPlatformLogAssert(
    _In_z_ const char* File,
    _In_ int Line,
    _In_z_ const char* Expr
    )
{ 
    QuicTraceEvent(LibraryAssert, "[ lib] ASSERT, %d:%s - %s.", (uint32_t)Line, File, Expr);
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

#if 0
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
#endif
