/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Abstraction Layer.

Environment:

    Windows User Mode

--*/

#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "platform_winuser.c.clog.h"
#endif

uint64_t QuicPlatformPerfFreq;
uint64_t QuicTotalMemory;
QUIC_PLATFORM QuicPlatform = { NULL };
QUIC_PROCESSOR_INFO* QuicProcessorInfo;
uint64_t* QuicNumaMasks;
uint32_t* QuicProcessorGroupOffsets;

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatformSystemLoad(
    void
    )
{
#ifdef QUIC_EVENTS_MANIFEST_ETW
    EventRegisterMicrosoft_Quic();
#endif

    (void)QueryPerformanceFrequency((LARGE_INTEGER*)&QuicPlatformPerfFreq);
    QuicPlatform.Heap = NULL;

    QuicTraceLogInfo(
        WindowsUserLoaded,
        "[ dll] Loaded");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatformSystemUnload(
    void
    )
{
    QuicTraceLogInfo(
        WindowsUserUnloaded,
        "[ dll] Unloaded");

#ifdef QUIC_EVENTS_MANIFEST_ETW
    EventUnregisterMicrosoft_Quic();
#endif
}

BOOLEAN
QuicProcessorInfoInit(
    void
    )
{
    BOOLEAN Result = FALSE;
    DWORD BufferLength = 0;
    uint8_t* Buffer = NULL;
    uint32_t Offset;

    uint32_t ActiveProcessorCount = QuicProcActiveCount();
    uint32_t ProcessorGroupCount = 0;
    uint32_t ProcessorsPerGroup = 0;
    uint32_t NumaNodeCount = 0;

    QuicProcessorInfo = QUIC_ALLOC_NONPAGED(ActiveProcessorCount * sizeof(QUIC_PROCESSOR_INFO));
    if (QuicProcessorInfo == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QuicProcessorInfo",
            ActiveProcessorCount * sizeof(QUIC_PROCESSOR_INFO));
        goto Error;
    }

    GetLogicalProcessorInformationEx(RelationAll, NULL, &BufferLength);
    if (BufferLength == 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX size");
        goto Error;
    }

    Buffer = QUIC_ALLOC_NONPAGED(BufferLength);
    if (Buffer == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX",
            BufferLength);
        goto Error;
    }

    if (!GetLogicalProcessorInformationEx(
            RelationAll,
            (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)Buffer,
            &BufferLength)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "GetLogicalProcessorInformationEx failed");
        goto Error;
    }

    Offset = 0;
    while (Offset < BufferLength) {
        PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Info =
            (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(Buffer + Offset);
        if (Info->Relationship == RelationNumaNode) {
            if (Info->NumaNode.NodeNumber + 1 > NumaNodeCount) {
                NumaNodeCount = Info->NumaNode.NodeNumber + 1;
            }
        } else if (Info->Relationship == RelationGroup) {
            if (ProcessorGroupCount == 0) {
                QUIC_DBG_ASSERT(Info->Group.ActiveGroupCount != 0);
                ProcessorGroupCount = Info->Group.ActiveGroupCount;
                ProcessorsPerGroup = Info->Group.GroupInfo[0].ActiveProcessorCount;
            }
        }
        Offset += Info->Size;
    }

    QUIC_DBG_ASSERT(ProcessorGroupCount != 0);
    if (ProcessorGroupCount == 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine processor group count");
        goto Error;
    }

    QUIC_DBG_ASSERT(ProcessorsPerGroup != 0);
    if (ProcessorsPerGroup == 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine processors per group count");
        goto Error;
    }

    QUIC_DBG_ASSERT(NumaNodeCount != 0);
    if (NumaNodeCount == 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine NUMA node count");
        goto Error;
    }

    QuicProcessorGroupOffsets = QUIC_ALLOC_NONPAGED(ProcessorGroupCount * sizeof(uint32_t));
    if (QuicProcessorGroupOffsets == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QuicProcessorGroupOffsets",
            ProcessorGroupCount * sizeof(uint32_t));
        goto Error;
    }

    for (uint32_t i = 0; i < ProcessorGroupCount; ++i) {
        QuicProcessorGroupOffsets[i] = i * ProcessorsPerGroup;
    }

    QuicNumaMasks = QUIC_ALLOC_NONPAGED(NumaNodeCount * sizeof(uint64_t));
    if (QuicNumaMasks == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QuicNumaMasks",
            NumaNodeCount * sizeof(uint64_t));
        goto Error;
    }

    QuicTraceLogInfo(
        WindowsUserProcessorState,
        "[ dll] Processors:%u, Groups:%u, NUMA Nodes:%u",
        ActiveProcessorCount, ProcessorGroupCount, NumaNodeCount);

    Offset = 0;
    while (Offset < BufferLength) {
        PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Info =
            (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(Buffer + Offset);
        if (Info->Relationship == RelationNumaNode) {
            QuicNumaMasks[Info->NumaNode.NodeNumber] = (uint64_t)Info->NumaNode.GroupMask.Mask;
        }
        Offset += Info->Size;
    }

    for (uint32_t Index = 0; Index < ActiveProcessorCount; ++Index) {

        Offset = 0;
        while (Offset < BufferLength) {
            PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Info =
                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(Buffer + Offset);
            if (Info->Relationship == RelationGroup) {
                uint32_t ProcessorOffset = 0;
                for (WORD i = 0; i < Info->Group.ActiveGroupCount; ++i) {
                    uint32_t IndexToSet = Index - ProcessorOffset;
                    QUIC_DBG_ASSERT(IndexToSet < 64);
                    if (IndexToSet < Info->Group.GroupInfo[i].ActiveProcessorCount) {
                        QuicProcessorInfo[Index].Group = i;
                        QuicProcessorInfo[Index].Index = IndexToSet;
                        QuicProcessorInfo[Index].MaskInGroup = 1ull << IndexToSet;
                        goto FindNumaNode;
                    }
                    ProcessorOffset += Info->Group.GroupInfo[i].ActiveProcessorCount;
                }
            }
            Offset += Info->Size;
        }

        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine processor group");
        goto Error;

FindNumaNode:

        Offset = 0;
        while (Offset < BufferLength) {
            PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Info =
                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(Buffer + Offset);
            if (Info->Relationship == RelationNumaNode) {
                if (Info->NumaNode.GroupMask.Group == QuicProcessorInfo[Index].Group &&
                    (Info->NumaNode.GroupMask.Mask & QuicProcessorInfo[Index].MaskInGroup) != 0) {
                    QuicProcessorInfo[Index].NumaNode = Info->NumaNode.NodeNumber;
                    QuicTraceLogInfo(
                        ProcessorInfo,
                        "[ dll] Proc[%u] Group[%hu] Index[%u] NUMA[%u]",
                        Index,
                        QuicProcessorInfo[Index].Group,
                        QuicProcessorInfo[Index].Index,
                        QuicProcessorInfo[Index].NumaNode);
                    goto Next;
                }
            }
            Offset += Info->Size;
        }

        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine NUMA node");
        goto Error;

Next:
        ;
    }

    Result = TRUE;

Error:

    QUIC_FREE(Buffer);

    if (!Result) {
        QUIC_FREE(QuicNumaMasks);
        QuicNumaMasks = NULL;
        QUIC_FREE(QuicProcessorGroupOffsets);
        QuicProcessorGroupOffsets = NULL;
        QUIC_FREE(QuicProcessorInfo);
        QuicProcessorInfo = NULL;
    }

    return Result;
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

    if (!QuicProcessorInfoInit()) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "QuicProcessorInfoInit failed");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    if (!GlobalMemoryStatusEx(&memInfo)) {
        DWORD Error = GetLastError();
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "GlobalMemoryStatusEx failed");
        Status = HRESULT_FROM_WIN32(Error);
        goto Error;
    }

    Status = QuicTlsLibraryInitialize();
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    QuicTotalMemory = memInfo.ullTotalPageFile;

    QuicTraceLogInfo(
        WindowsUserInitialized,
        "[ dll] Initialized (AvailMem = %llu bytes)",
        QuicTotalMemory);

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
    QUIC_FREE(QuicNumaMasks);
    QuicNumaMasks = NULL;
    QUIC_FREE(QuicProcessorGroupOffsets);
    QuicProcessorGroupOffsets = NULL;
    QUIC_FREE(QuicProcessorInfo);
    QuicProcessorInfo = NULL;
    HeapDestroy(QuicPlatform.Heap);
    QuicPlatform.Heap = NULL;
    QuicTraceLogInfo(
        WindowsUserUninitialized,
        "[ dll] Uninitialized");
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPlatformLogAssert(
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
