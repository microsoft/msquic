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

uint64_t CxPlatPerfFreq;
uint64_t CxPlatTotalMemory;
CX_PLATFORM CxPlatform = { NULL };
CXPLAT_PROCESSOR_INFO* CxPlatProcessorInfo;
uint64_t* CxPlatNumaMasks;
uint32_t* CxPlatProcessorGroupOffsets;

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSystemLoad(
    void
    )
{
#ifdef QUIC_EVENTS_MANIFEST_ETW
    EventRegisterMicrosoft_Quic();
#endif

    (void)QueryPerformanceFrequency((LARGE_INTEGER*)&CxPlatPerfFreq);
    CxPlatform.Heap = NULL;

    QuicTraceLogInfo(
        WindowsUserLoaded,
        "[ dll] Loaded");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSystemUnload(
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
CxPlatProcessorInfoInit(
    void
    )
{
    BOOLEAN Result = FALSE;
    DWORD BufferLength = 0;
    uint8_t* Buffer = NULL;
    uint32_t Offset;

    uint32_t ActiveProcessorCount = CxPlatProcActiveCount();
    uint32_t ProcessorGroupCount = 0;
    uint32_t ProcessorsPerGroup = 0;
    uint32_t NumaNodeCount = 0;

    CxPlatProcessorInfo =
        CXPLAT_ALLOC_NONPAGED(
            ActiveProcessorCount * sizeof(CXPLAT_PROCESSOR_INFO),
            QUIC_POOL_PLATFORM_PROC);
    if (CxPlatProcessorInfo == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CxPlatProcessorInfo",
            ActiveProcessorCount * sizeof(CXPLAT_PROCESSOR_INFO));
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

    Buffer = CXPLAT_ALLOC_NONPAGED(BufferLength, QUIC_POOL_PLATFORM_TMP_ALLOC);
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
                CXPLAT_DBG_ASSERT(Info->Group.ActiveGroupCount != 0);
                ProcessorGroupCount = Info->Group.ActiveGroupCount;
                ProcessorsPerGroup = Info->Group.GroupInfo[0].ActiveProcessorCount;
            }
        }
        Offset += Info->Size;
    }

    CXPLAT_DBG_ASSERT(ProcessorGroupCount != 0);
    if (ProcessorGroupCount == 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine processor group count");
        goto Error;
    }

    CXPLAT_DBG_ASSERT(ProcessorsPerGroup != 0);
    if (ProcessorsPerGroup == 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine processors per group count");
        goto Error;
    }

    CXPLAT_DBG_ASSERT(NumaNodeCount != 0);
    if (NumaNodeCount == 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine NUMA node count");
        goto Error;
    }

    CxPlatProcessorGroupOffsets = CXPLAT_ALLOC_NONPAGED(ProcessorGroupCount * sizeof(uint32_t), QUIC_POOL_PLATFORM_PROC);
    if (CxPlatProcessorGroupOffsets == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CxPlatProcessorGroupOffsets",
            ProcessorGroupCount * sizeof(uint32_t));
        goto Error;
    }

    for (uint32_t i = 0; i < ProcessorGroupCount; ++i) {
        CxPlatProcessorGroupOffsets[i] = i * ProcessorsPerGroup;
    }

    CxPlatNumaMasks = CXPLAT_ALLOC_NONPAGED(NumaNodeCount * sizeof(uint64_t), QUIC_POOL_PLATFORM_PROC);
    if (CxPlatNumaMasks == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CxPlatNumaMasks",
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
            CxPlatNumaMasks[Info->NumaNode.NodeNumber] = (uint64_t)Info->NumaNode.GroupMask.Mask;
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
                    if (IndexToSet < Info->Group.GroupInfo[i].ActiveProcessorCount) {
                        CXPLAT_DBG_ASSERT(IndexToSet < 64);
                        CxPlatProcessorInfo[Index].Group = i;
                        CxPlatProcessorInfo[Index].Index = IndexToSet;
                        CxPlatProcessorInfo[Index].MaskInGroup = 1ull << IndexToSet;
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
                if (Info->NumaNode.GroupMask.Group == CxPlatProcessorInfo[Index].Group &&
                    (Info->NumaNode.GroupMask.Mask & CxPlatProcessorInfo[Index].MaskInGroup) != 0) {
                    CxPlatProcessorInfo[Index].NumaNode = Info->NumaNode.NodeNumber;
                    QuicTraceLogInfo(
                        ProcessorInfo,
                        "[ dll] Proc[%u] Group[%hu] Index[%u] NUMA[%u]",
                        Index,
                        CxPlatProcessorInfo[Index].Group,
                        CxPlatProcessorInfo[Index].Index,
                        CxPlatProcessorInfo[Index].NumaNode);
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

    CXPLAT_FREE(Buffer, QUIC_POOL_PLATFORM_TMP_ALLOC);

    if (!Result) {
        CXPLAT_FREE(CxPlatNumaMasks, QUIC_POOL_PLATFORM_PROC);
        CxPlatNumaMasks = NULL;
        CXPLAT_FREE(CxPlatProcessorGroupOffsets, QUIC_POOL_PLATFORM_PROC);
        CxPlatProcessorGroupOffsets = NULL;
        CXPLAT_FREE(CxPlatProcessorInfo, QUIC_POOL_PLATFORM_PROC);
        CxPlatProcessorInfo = NULL;
    }

    return Result;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatInitialize(
    void
    )
{
    QUIC_STATUS Status;
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);

    CxPlatform.Heap = HeapCreate(0, 0, 0);
    if (CxPlatform.Heap == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    if (!CxPlatProcessorInfoInit()) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "CxPlatProcessorInfoInit failed");
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

    Status = CxPlatTlsLibraryInitialize();
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    CxPlatTotalMemory = memInfo.ullTotalPageFile;

    QuicTraceLogInfo(
        WindowsUserInitialized,
        "[ dll] Initialized (AvailMem = %llu bytes)",
        CxPlatTotalMemory);

Error:

    if (QUIC_FAILED(Status)) {
        if (CxPlatform.Heap) {
            HeapDestroy(CxPlatform.Heap);
            CxPlatform.Heap = NULL;
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatUninitialize(
    void
    )
{
    CxPlatTlsLibraryUninitialize();
    CXPLAT_DBG_ASSERT(CxPlatform.Heap);
    CXPLAT_FREE(CxPlatNumaMasks, QUIC_POOL_PLATFORM_PROC);
    CxPlatNumaMasks = NULL;
    CXPLAT_FREE(CxPlatProcessorGroupOffsets, QUIC_POOL_PLATFORM_PROC);
    CxPlatProcessorGroupOffsets = NULL;
    CXPLAT_FREE(CxPlatProcessorInfo, QUIC_POOL_PLATFORM_PROC);
    CxPlatProcessorInfo = NULL;
    HeapDestroy(CxPlatform.Heap);
    CxPlatform.Heap = NULL;
    QuicTraceLogInfo(
        WindowsUserUninitialized,
        "[ dll] Uninitialized");
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
CxPlatRandom(
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
CxPlatRandom(
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

#ifdef DEBUG
#define AllocOffset (sizeof(void*) * 2)
#endif

_Ret_maybenull_
_Post_writable_byte_size_(ByteCount)
DECLSPEC_ALLOCATOR
void*
CxPlatAlloc(
    _In_ size_t ByteCount,
    _In_ uint32_t Tag
    )
{
    CXPLAT_DBG_ASSERT(CxPlatform.Heap);
#ifdef QUIC_RANDOM_ALLOC_FAIL
    uint8_t Rand; CxPlatRandom(sizeof(Rand), &Rand);
    if ((Rand % 100) == 1) return NULL;
#else
#ifdef DEBUG
    void* Alloc = HeapAlloc(CxPlatform.Heap, 0, ByteCount + AllocOffset);
    *((uint32_t*)Alloc) = Tag;
    return (void*)((uint8_t*)Alloc + AllocOffset);
#else
    UNREFERENCED_PARAMETER(Tag);
    return HeapAlloc(CxPlatform.Heap, 0, ByteCount);
#endif
#endif // QUIC_RANDOM_ALLOC_FAIL
}

void
CxPlatFree(
    __drv_freesMem(Mem) _Frees_ptr_opt_ void* Mem,
    _In_ uint32_t Tag
    )
{
#ifdef DEBUG
    void* ActualAlloc = (void*)((uint8_t*)Mem - AllocOffset);
    uint32_t TagToCheck = *((uint32_t*)ActualAlloc);
    CXPLAT_DBG_ASSERT(TagToCheck == Tag);
    (void)HeapFree(CxPlatform.Heap, 0, ActualAlloc);
#else
    UNREFERENCED_PARAMETER(Tag);
    (void)HeapFree(CxPlatform.Heap, 0, Mem);
#endif
}

__declspec(noreturn)
void
KrmlExit(
    int n
    )
{
    UNREFERENCED_PARAMETER(n);
    CXPLAT_FRE_ASSERTMSG(FALSE, "miTLS hit a fatal error");
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
