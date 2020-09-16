/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains Windows User Mode implementations of the
    QUIC Platform Interfaces.

Environment:

    Windows user mode

--*/

#pragma once

#ifndef QUIC_PLATFORM_TYPE
#error "Must be included from quic_platform.h"
#endif

#ifdef _KERNEL_MODE
#error "Incorrectly including Windows User Platform Header"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#ifdef QUIC_UWP_BUILD
#undef WINAPI_FAMILY
#define WINAPI_FAMILY WINAPI_FAMILY_DESKTOP_APP
#endif

#pragma warning(push) // Don't care about OACR warnings in publics
#pragma warning(disable:26036)
#pragma warning(disable:28252)
#pragma warning(disable:28253)
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <winternl.h>
#ifdef _M_X64
#include <intrin.h>
#endif
#ifdef QUIC_TELEMETRY_ASSERTS
#include <telemetry\MicrosoftTelemetryAssert.h>
#endif
#include <msquic_winuser.h>
#pragma warning(pop)

#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union
#pragma warning(disable:4324)  // 'QUIC_POOL': structure was padded due to alignment specifier

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(DEBUG) || defined(_DEBUG)
#define DBG 1
#define DEBUG 1
#endif

#if _WIN64
#define QUIC_64BIT 1
#else
#define QUIC_32BIT 1
#endif

#define INITCODE
#define PAGEDX

#define QUIC_CACHEALIGN DECLSPEC_CACHEALIGN

#define ALIGN_DOWN(length, type) \
    ((ULONG)(length) & ~(sizeof(type) - 1))

#define ALIGN_UP(length, type) \
    (ALIGN_DOWN(((ULONG)(length) + sizeof(type) - 1), type))

//
// Library Initialization
//

//
// Called in DLLMain or DriverEntry.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatformSystemLoad(
    void
    );

//
// Called in DLLMain or DriverUnload.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatformSystemUnload(
    void
    );

//
// Initializes the PAL library. Calls to this and
// QuicPlatformUninitialize must be serialized and cannot overlap.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicPlatformInitialize(
    void
    );

//
// Uninitializes the PAL library. Calls to this and
// QuicPlatformInitialize must be serialized and cannot overlap.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatformUninitialize(
    void
    );

//
// Assertion Interfaces
//

#define QUIC_STATIC_ASSERT(X,Y) static_assert(X,Y)

#define QUIC_ANALYSIS_ASSERT(X) __analysis_assert(X)

//
// Logs the assertion failure to ETW.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPlatformLogAssert(
    _In_z_ const char* File,
    _In_ int Line,
    _In_z_ const char* Expr
    );

#define QUIC_ASSERT_ACTION(_exp) \
    ((!(_exp)) ? \
        (QuicPlatformLogAssert(__FILE__, __LINE__, #_exp), \
         __annotation(L"Debug", L"AssertFail", L#_exp), \
         DbgRaiseAssertionFailure(), FALSE) : \
        TRUE)

#define QUIC_ASSERTMSG_ACTION(_msg, _exp) \
    ((!(_exp)) ? \
        (QuicPlatformLogAssert(__FILE__, __LINE__, #_exp), \
         __annotation(L"Debug", L"AssertFail", L##_msg), \
         DbgRaiseAssertionFailure(), FALSE) : \
        TRUE)

#if defined(_PREFAST_)
// _Analysis_assume_ will never result in any code generation for _exp,
// so using it will not have runtime impact, even if _exp has side effects.
#define QUIC_ANALYSIS_ASSUME(_exp) _Analysis_assume_(_exp)
#else // _PREFAST_
// QUIC_ANALYSIS_ASSUME ensures that _exp is parsed in non-analysis compile.
// On DEBUG, it's guaranteed to be parsed as part of the normal compile, but
// with non-DEBUG, use __noop to ensure _exp is parseable but without code
// generation.
#if DEBUG
#define QUIC_ANALYSIS_ASSUME(_exp) ((void) 0)
#else // DEBUG
#define QUIC_ANALYSIS_ASSUME(_exp) __noop(_exp)
#endif // DEBUG
#endif // _PREFAST_

#define QUIC_NO_SANITIZE(X)


//
// MsQuic uses three types of asserts:
//
//  QUIC_DBG_ASSERT - Asserts that are too expensive to evaluate all the time.
//  QUIC_TEL_ASSERT - Asserts that are acceptable to always evaluate, but not
//                    always crash the process.
//  QUIC_FRE_ASSERT - Asserts that must always crash the process.
//

#if DEBUG
#define QUIC_DBG_ASSERT(_exp)          (QUIC_ANALYSIS_ASSUME(_exp), QUIC_ASSERT_ACTION(_exp))
#define QUIC_DBG_ASSERTMSG(_exp, _msg) (QUIC_ANALYSIS_ASSUME(_exp), QUIC_ASSERTMSG_ACTION(_msg, _exp))
#else
#define QUIC_DBG_ASSERT(_exp)          (QUIC_ANALYSIS_ASSUME(_exp), 0)
#define QUIC_DBG_ASSERTMSG(_exp, _msg) (QUIC_ANALYSIS_ASSUME(_exp), 0)
#endif

#if DEBUG
#define QUIC_TEL_ASSERT(_exp)          (QUIC_ANALYSIS_ASSUME(_exp), QUIC_ASSERT_ACTION(_exp))
#define QUIC_TEL_ASSERTMSG(_exp, _msg) (QUIC_ANALYSIS_ASSUME(_exp), QUIC_ASSERTMSG_ACTION(_msg, _exp))
#define QUIC_TEL_ASSERTMSG_ARGS(_exp, _msg, _origin, _bucketArg1, _bucketArg2) \
     (QUIC_ANALYSIS_ASSUME(_exp), QUIC_ASSERTMSG_ACTION(_msg, _exp))
#else
#ifdef MICROSOFT_TELEMETRY_ASSERT
#define QUIC_TEL_ASSERT(_exp)          (QUIC_ANALYSIS_ASSUME(_exp), MICROSOFT_TELEMETRY_ASSERT(_exp))
#define QUIC_TEL_ASSERTMSG(_exp, _msg) (QUIC_ANALYSIS_ASSUME(_exp), MICROSOFT_TELEMETRY_ASSERT_MSG(_exp, _msg))
#define QUIC_TEL_ASSERTMSG_ARGS(_exp, _msg, _origin, _bucketArg1, _bucketArg2) \
    (QUIC_ANALYSIS_ASSUME(_exp), MICROSOFT_TELEMETRY_ASSERT_MSG_WITH_ARGS(_exp, _msg, _origin, _bucketArg1, _bucketArg2))
#else
#define QUIC_TEL_ASSERT(_exp)          (QUIC_ANALYSIS_ASSUME(_exp), 0)
#define QUIC_TEL_ASSERTMSG(_exp, _msg) (QUIC_ANALYSIS_ASSUME(_exp), 0)
#define QUIC_TEL_ASSERTMSG_ARGS(_exp, _msg, _origin, _bucketArg1, _bucketArg2) \
    (QUIC_ANALYSIS_ASSUME(_exp), 0)
#endif
#endif

#define QUIC_FRE_ASSERT(_exp)          (QUIC_ANALYSIS_ASSUME(_exp), QUIC_ASSERT_ACTION(_exp))
#define QUIC_FRE_ASSERTMSG(_exp, _msg) (QUIC_ANALYSIS_ASSUME(_exp), QUIC_ASSERTMSG_ACTION(_msg, _exp))

//
// Verifier is enabled.
//
#define QuicVerifierEnabled(Flags) \
    (GetModuleHandleW(L"verifier.dll") != NULL && \
     GetModuleHandleW(L"vrfcore.dll") != NULL), \
    Flags = 0

//
// Debugger check.
//
#define QuicDebuggerPresent() IsDebuggerPresent()

//
// Interrupt ReQuest Level
//

#define QUIC_IRQL() PASSIVE_LEVEL

#define QUIC_PASSIVE_CODE() QUIC_DBG_ASSERT(QUIC_IRQL() == PASSIVE_LEVEL)

//
// Allocation/Memory Interfaces
//

extern uint64_t QuicTotalMemory;

_Ret_maybenull_
_Post_writable_byte_size_(ByteCount)
DECLSPEC_ALLOCATOR
void*
QuicAlloc(
    _In_ size_t ByteCount
    );

void
QuicFree(
    __drv_freesMem(Mem) _Frees_ptr_opt_ void* Mem
    );

#define QUIC_ALLOC_PAGED(Size) QuicAlloc(Size)
#define QUIC_ALLOC_NONPAGED(Size) QuicAlloc(Size)
#define QUIC_FREE(Mem) QuicFree((void*)Mem)
#define QUIC_FREE_TAG(Mem, Tag) QUIC_FREE(Mem)

typedef struct QUIC_POOL {
    SLIST_HEADER ListHead;
    uint32_t Size;
} QUIC_POOL;

#define QUIC_POOL_MAXIMUM_DEPTH   256 // Copied from EX_MAXIMUM_LOOKASIDE_DEPTH_BASE

#if DEBUG
typedef struct QUIC_POOL_ENTRY {
    SLIST_ENTRY ListHead;
    uint32_t SpecialFlag;
} QUIC_POOL_ENTRY;
#define QUIC_POOL_SPECIAL_FLAG    0xAAAAAAAA
#endif

inline
void
QuicPoolInitialize(
    _In_ BOOLEAN IsPaged,
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ QUIC_POOL* Pool
    )
{
#if DEBUG
    QUIC_DBG_ASSERT(Size >= sizeof(QUIC_POOL_ENTRY));
#endif
    Pool->Size = Size;
    InitializeSListHead(&(Pool)->ListHead);
    UNREFERENCED_PARAMETER(IsPaged);
    UNREFERENCED_PARAMETER(Tag); // TODO - Use in debug mode?
}

inline
void
QuicPoolUninitialize(
    _Inout_ QUIC_POOL* Pool
    )
{
    void* Entry;
    while ((Entry = InterlockedPopEntrySList(&Pool->ListHead)) != NULL) {
        QuicFree(Entry);
    }
}

inline
void*
QuicPoolAlloc(
    _Inout_ QUIC_POOL* Pool
    )
{
#if QUIC_DISABLE_MEM_POOL
    return QuicAlloc(Pool->Size);
#else
    void* Entry = InterlockedPopEntrySList(&Pool->ListHead);
    if (Entry == NULL) {
        Entry = QuicAlloc(Pool->Size);
    }
#if DEBUG
    if (Entry != NULL) {
        ((QUIC_POOL_ENTRY*)Entry)->SpecialFlag = 0;
    }
#endif
    return Entry;
#endif
}

inline
void
QuicPoolFree(
    _Inout_ QUIC_POOL* Pool,
    _In_ void* Entry
    )
{
#if QUIC_DISABLE_MEM_POOL
    UNREFERENCED_PARAMETER(Pool);
    QuicFree(Entry);
    return;
#else
#if DEBUG
    QUIC_DBG_ASSERT(((QUIC_POOL_ENTRY*)Entry)->SpecialFlag != QUIC_POOL_SPECIAL_FLAG);
    ((QUIC_POOL_ENTRY*)Entry)->SpecialFlag = QUIC_POOL_SPECIAL_FLAG;
#endif
    if (QueryDepthSList(&Pool->ListHead) >= QUIC_POOL_MAXIMUM_DEPTH) {
        QuicFree(Entry);
    } else {
        InterlockedPushEntrySList(&Pool->ListHead, (PSLIST_ENTRY)Entry);
    }
#endif
}

#define QuicZeroMemory RtlZeroMemory
#define QuicCopyMemory RtlCopyMemory
#define QuicMoveMemory RtlMoveMemory
#define QuicSecureZeroMemory RtlSecureZeroMemory

#define QuicByteSwapUint16 _byteswap_ushort
#define QuicByteSwapUint32 _byteswap_ulong
#define QuicByteSwapUint64 _byteswap_uint64

//
// Locking Interfaces
//

typedef CRITICAL_SECTION QUIC_LOCK;

#define QuicLockInitialize(Lock) InitializeCriticalSection(Lock)
#define QuicLockUninitialize(Lock) DeleteCriticalSection(Lock)
#define QuicLockAcquire(Lock) EnterCriticalSection(Lock)
#define QuicLockRelease(Lock) LeaveCriticalSection(Lock)

typedef CRITICAL_SECTION QUIC_DISPATCH_LOCK;

#define QuicDispatchLockInitialize(Lock) InitializeCriticalSection(Lock)
#define QuicDispatchLockUninitialize(Lock) DeleteCriticalSection(Lock)
#define QuicDispatchLockAcquire(Lock) EnterCriticalSection(Lock)
#define QuicDispatchLockRelease(Lock) LeaveCriticalSection(Lock)

typedef SRWLOCK QUIC_RW_LOCK;

#define QuicRwLockInitialize(Lock) InitializeSRWLock(Lock)
#define QuicRwLockUninitialize(Lock)
#define QuicRwLockAcquireShared(Lock) AcquireSRWLockShared(Lock)
#define QuicRwLockAcquireExclusive(Lock) AcquireSRWLockExclusive(Lock)
#define QuicRwLockReleaseShared(Lock) ReleaseSRWLockShared(Lock)
#define QuicRwLockReleaseExclusive(Lock) ReleaseSRWLockExclusive(Lock)

typedef SRWLOCK QUIC_DISPATCH_RW_LOCK;

#define QuicDispatchRwLockInitialize(Lock) InitializeSRWLock(Lock)
#define QuicDispatchRwLockUninitialize(Lock)
#define QuicDispatchRwLockAcquireShared(Lock) AcquireSRWLockShared(Lock)
#define QuicDispatchRwLockAcquireExclusive(Lock) AcquireSRWLockExclusive(Lock)
#define QuicDispatchRwLockReleaseShared(Lock) ReleaseSRWLockShared(Lock)
#define QuicDispatchRwLockReleaseExclusive(Lock) ReleaseSRWLockExclusive(Lock)

//
// Reference Count Interface
//

#if defined(_X86_) || defined(_AMD64_)
#define QuicBarrierAfterInterlock()
#elif defined(_ARM64_)
#define QuicBarrierAfterInterlock()  __dmb(_ARM64_BARRIER_ISH)
#elif defined(_ARM_)
#define QuicBarrierAfterInterlock()  __dmb(_ARM_BARRIER_ISH)
#else
#error Unsupported architecture.
#endif

#if defined (_WIN64)
#define QuicIncrementLongPtrNoFence InterlockedIncrementNoFence64
#define QuicDecrementLongPtrRelease InterlockedDecrementRelease64
#define QuicCompareExchangeLongPtrNoFence InterlockedCompareExchangeNoFence64
#define QuicReadLongPtrNoFence ReadNoFence64
#else
#define QuicIncrementLongPtrNoFence InterlockedIncrementNoFence
#define QuicDecrementLongPtrRelease InterlockedDecrementRelease
#define QuicCompareExchangeLongPtrNoFence InterlockedCompareExchangeNoFence
#define QuicReadLongPtrNoFence ReadNoFence
#endif

typedef LONG_PTR QUIC_REF_COUNT;

inline
void
QuicRefInitialize(
    _Out_ QUIC_REF_COUNT* RefCount
    )
{
    *RefCount = 1;
}

#define QuicRefUninitialize(RefCount)

inline
void
QuicRefIncrement(
    _Inout_ QUIC_REF_COUNT* RefCount
    )
{
    if (QuicIncrementLongPtrNoFence(RefCount) > 1) {
        return;
    }

    __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
}

inline
BOOLEAN
QuicRefIncrementNonZero(
    _Inout_ volatile QUIC_REF_COUNT *RefCount,
    _In_ ULONG Bias
    )
{
    QUIC_REF_COUNT NewValue;
    QUIC_REF_COUNT OldValue;

    PrefetchForWrite(RefCount);
    OldValue = QuicReadLongPtrNoFence(RefCount);
    for (;;) {
        NewValue = OldValue + Bias;
        if ((ULONG_PTR)NewValue > Bias) {
            NewValue = QuicCompareExchangeLongPtrNoFence(RefCount,
                                                         NewValue,
                                                         OldValue);
            if (NewValue == OldValue) {
                return TRUE;
            }

            OldValue = NewValue;

        } else if ((ULONG_PTR)NewValue == Bias) {
            return FALSE;

        } else {
            __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
            return FALSE;
        }
    }
}

inline
BOOLEAN
QuicRefDecrement(
    _Inout_ QUIC_REF_COUNT* RefCount
    )
{
    QUIC_REF_COUNT NewValue;

    //
    // A release fence is required to ensure all guarded memory accesses are
    // complete before any thread can begin destroying the object.
    //

    NewValue = QuicDecrementLongPtrRelease(RefCount);
    if (NewValue > 0) {
        return FALSE;

    } else if (NewValue == 0) {

        //
        // An acquire fence is required before object destruction to ensure
        // that the destructor cannot observe values changing on other threads.
        //

        QuicBarrierAfterInterlock();
        return TRUE;
    }

    __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    return FALSE;
}

//
// Event Interfaces
//

typedef HANDLE QUIC_EVENT;

#define QuicEventInitialize(Event, ManualReset, InitialState) \
    *(Event) = CreateEvent(NULL, ManualReset, InitialState, NULL)
#define QuicEventUninitialize(Event) CloseHandle(Event)
#define QuicEventSet(Event) SetEvent(Event)
#define QuicEventReset(Event) ResetEvent(Event)
#define QuicEventWaitForever(Event) WaitForSingleObject(Event, INFINITE)
#define QuicEventWaitWithTimeout(Event, timeoutMs) \
    (WAIT_OBJECT_0 == WaitForSingleObject(Event, timeoutMs))

//
// Time Measurement Interfaces
//

//
// This is an undocumented API that is used to query the current timer
// resolution.
//
#if !defined(QUIC_WINDOWS_INTERNAL)
__kernel_entry
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryTimerResolution(
    _Out_ PULONG MaximumTime,
    _Out_ PULONG MinimumTime,
    _Out_ PULONG CurrentTime
    );
#endif

//
// Returns the worst-case system timer resolution (in us).
//
inline
uint64_t
QuicGetTimerResolution()
{
    ULONG MaximumTime, MinimumTime, CurrentTime;
    NtQueryTimerResolution(&MaximumTime, &MinimumTime, &CurrentTime);
    return NS100_TO_US(MaximumTime);
}

//
// Performance counter frequency.
//
extern uint64_t QuicPlatformPerfFreq;

//
// Returns the current time in platform specific time units.
//
inline
uint64_t
QuicTimePlat(
    void
    )
{
    uint64_t Count;
    QueryPerformanceCounter((LARGE_INTEGER*)&Count);
    return Count;
}

//
// Converts platform time to microseconds.
//
inline
uint64_t
QuicTimePlatToUs64(
    uint64_t Count
    )
{
    //
    // Multiply by a big number (1000000, to convert seconds to microseconds)
    // and divide by a big number (QuicPlatformPerfFreq, to convert counts to secs).
    //
    // Avoid overflow with separate multiplication/division of the high and low
    // bits. Taken from TcpConvertPerformanceCounterToMicroseconds.
    //
    uint64_t High = (Count >> 32) * 1000000;
    uint64_t Low = (Count & 0xFFFFFFFF) * 1000000;
    return
        ((High / QuicPlatformPerfFreq) << 32) +
        ((Low + ((High % QuicPlatformPerfFreq) << 32)) / QuicPlatformPerfFreq);
}

//
// Converts microseconds to platform time.
//
inline
uint64_t
QuicTimeUs64ToPlat(
    uint64_t TimeUs
    )
{
    uint64_t High = (TimeUs >> 32) * QuicPlatformPerfFreq;
    uint64_t Low = (TimeUs & 0xFFFFFFFF) * QuicPlatformPerfFreq;
    return
        ((High / 1000000) << 32) +
        ((Low + ((High % 1000000) << 32)) / QuicPlatformPerfFreq);
}

#define QuicTimeUs64() QuicTimePlatToUs64(QuicTimePlat())
#define QuicTimeUs32() (uint32_t)QuicTimeUs64()
#define QuicTimeMs64() US_TO_MS(QuicTimeUs64())
#define QuicTimeMs32() (uint32_t)QuicTimeMs64()

#define UNIX_EPOCH_AS_FILE_TIME 0x19db1ded53e8000ll

inline
int64_t
QuicTimeEpochMs64(
    )
{
    LARGE_INTEGER FileTime;
    GetSystemTimeAsFileTime((FILETIME*) &FileTime);
    return NS100_TO_MS(FileTime.QuadPart - UNIX_EPOCH_AS_FILE_TIME);
}

//
// Returns the difference between two timestamps.
//
inline
uint64_t
QuicTimeDiff64(
    _In_ uint64_t T1,     // First time measured
    _In_ uint64_t T2      // Second time measured
    )
{
    //
    // Assume no wrap around.
    //
    return T2 - T1;
}

//
// Returns the difference between two timestamps.
//
inline
uint32_t
QuicTimeDiff32(
    _In_ uint32_t T1,     // First time measured
    _In_ uint32_t T2      // Second time measured
    )
{
    if (T2 > T1) {
        return T2 - T1;
    } else { // Wrap around case.
        return T2 + (0xFFFFFFFF - T1) + 1;
    }
}

//
// Returns TRUE if T1 came before T2.
//
inline
BOOLEAN
QuicTimeAtOrBefore64(
    _In_ uint64_t T1,
    _In_ uint64_t T2
    )
{
    //
    // Assume no wrap around.
    //
    return T1 <= T2;
}

//
// Returns TRUE if T1 came before T2.
//
inline
BOOLEAN
QuicTimeAtOrBefore32(
    _In_ uint32_t T1,
    _In_ uint32_t T2
    )
{
    return (int32_t)(T1 - T2) <= 0;
}

#define QuicSleep(ms) Sleep(ms)

//
// Processor Count and Index
//

typedef struct {

    uint16_t Group;
    uint32_t Index; // In Group;
    uint32_t NumaNode;
    uint64_t MaskInGroup;

} QUIC_PROCESSOR_INFO;

extern QUIC_PROCESSOR_INFO* QuicProcessorInfo;
extern uint64_t* QuicNumaMasks;
extern uint32_t* QuicProcessorGroupOffsets;

#define QuicProcMaxCount() GetMaximumProcessorCount(ALL_PROCESSOR_GROUPS)
#define QuicProcActiveCount() GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
uint32_t
QuicProcCurrentNumber(
    void
    ) {
    PROCESSOR_NUMBER ProcNumber;
    GetCurrentProcessorNumberEx(&ProcNumber);
    return QuicProcessorGroupOffsets[ProcNumber.Group] + ProcNumber.Number;
}


//
// Create Thread Interfaces
//

//
// This is the undocumented interface for setting a thread's name. This is
// essentially what SetThreadDescription does, but that is not available in
// older versions of Windows.
//
#if !defined(QUIC_WINDOWS_INTERNAL) && !defined(QUIC_UWP_BUILD)
#define ThreadNameInformation ((THREADINFOCLASS)38)

typedef struct _THREAD_NAME_INFORMATION {
    UNICODE_STRING ThreadName;
} THREAD_NAME_INFORMATION, *PTHREAD_NAME_INFORMATION;

__kernel_entry
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength
    );
#endif

typedef struct QUIC_THREAD_CONFIG {
    uint16_t Flags;
    uint16_t IdealProcessor;
    _Field_z_ const char* Name;
    LPTHREAD_START_ROUTINE Callback;
    void* Context;
} QUIC_THREAD_CONFIG;

typedef HANDLE QUIC_THREAD;
#define QUIC_THREAD_CALLBACK(FuncName, CtxVarName)  \
    DWORD                                           \
    WINAPI                                          \
    FuncName(                                       \
      _In_ void* CtxVarName                         \
      )

#define QUIC_THREAD_RETURN(Status) return (DWORD)(Status)

inline
QUIC_STATUS
QuicThreadCreate(
    _In_ QUIC_THREAD_CONFIG* Config,
    _Out_ QUIC_THREAD* Thread
    )
{
    *Thread =
        CreateThread(
            NULL,
            0,
            Config->Callback,
            Config->Context,
            0,
            NULL);
    if (*Thread == NULL) {
        return GetLastError();
    }
    const QUIC_PROCESSOR_INFO* ProcInfo = &QuicProcessorInfo[Config->IdealProcessor];
    GROUP_AFFINITY Group = {0};
    if (Config->Flags & QUIC_THREAD_FLAG_SET_AFFINITIZE) {
        Group.Mask = (KAFFINITY)(1ull << ProcInfo->Index);          // Fixed processor
    } else {
        Group.Mask = (KAFFINITY)QuicNumaMasks[ProcInfo->NumaNode];  // Fixed NUMA node
    }
    Group.Group = ProcInfo->Group;
    SetThreadGroupAffinity(*Thread, &Group, NULL);
    if (Config->Flags & QUIC_THREAD_FLAG_SET_IDEAL_PROC) {
        SetThreadIdealProcessor(*Thread, ProcInfo->Index);
    }
    if (Config->Flags & QUIC_THREAD_FLAG_HIGH_PRIORITY) {
        SetThreadPriority(*Thread, THREAD_PRIORITY_HIGHEST);
    }
    if (Config->Name) {
        WCHAR WideName[64] = L"";
        size_t WideNameLength;
        mbstowcs_s(
            &WideNameLength,
            WideName,
            ARRAYSIZE(WideName) - 1,
            Config->Name,
            _TRUNCATE);
#if defined(QUIC_UWP_BUILD)
        SetThreadDescription(*Thread, WideName);
#else
        THREAD_NAME_INFORMATION ThreadNameInfo;
        RtlInitUnicodeString(&ThreadNameInfo.ThreadName, WideName);
        NtSetInformationThread(
            *Thread,
            ThreadNameInformation,
            &ThreadNameInfo,
            sizeof(ThreadNameInfo));
#endif
    }
    return QUIC_STATUS_SUCCESS;
}
#define QuicThreadDelete(Thread) CloseHandle(*(Thread))
#define QuicThreadWait(Thread) WaitForSingleObject(*(Thread), INFINITE)
typedef uint32_t QUIC_THREAD_ID;
#define QuicCurThreadID() GetCurrentThreadId()

//
// Rundown Protection Interfaces
//

typedef struct QUIC_RUNDOWN_REF {

    //
    // The ref counter.
    //
    QUIC_REF_COUNT RefCount;

    //
    // The completion event.
    //
    HANDLE RundownComplete;

} QUIC_RUNDOWN_REF;

#define QuicRundownInitialize(Rundown) \
    QuicRefInitialize(&(Rundown)->RefCount); \
    (Rundown)->RundownComplete = CreateEvent(NULL, FALSE, FALSE, NULL)
#define QuicRundownInitializeDisabled(Rundown) \
    (Rundown)->RefCount = 0; \
    (Rundown)->RundownComplete = CreateEvent(NULL, FALSE, FALSE, NULL)
#define QuicRundownReInitialize(Rundown) (Rundown)->RefCount = 1
#define QuicRundownUninitialize(Rundown) CloseHandle((Rundown)->RundownComplete)
#define QuicRundownAcquire(Rundown) QuicRefIncrementNonZero(&(Rundown)->RefCount, 1)
#define QuicRundownRelease(Rundown) \
    if (QuicRefDecrement(&(Rundown)->RefCount)) { \
        SetEvent((Rundown)->RundownComplete); \
    }
#define QuicRundownReleaseAndWait(Rundown) \
    if (!QuicRefDecrement(&(Rundown)->RefCount)) { \
        WaitForSingleObject((Rundown)->RundownComplete, INFINITE); \
    }

//
// Crypto Interfaces
//

//
// Returns cryptographically random bytes.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicRandom(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    );

//
// Network Compartment ID interfaces
//

#ifndef QUIC_UWP_BUILD

#define QUIC_COMPARTMENT_ID NET_IF_COMPARTMENT_ID

#define QUIC_UNSPECIFIED_COMPARTMENT_ID NET_IF_COMPARTMENT_ID_UNSPECIFIED
#define QUIC_DEFAULT_COMPARTMENT_ID     NET_IF_COMPARTMENT_ID_PRIMARY

inline
QUIC_STATUS
QuicSetCurrentThreadProcessorAffinity(
    _In_ uint8_t ProcessorIndex
    )
{
    const QUIC_PROCESSOR_INFO* ProcInfo = &QuicProcessorInfo[ProcessorIndex];
    GROUP_AFFINITY Group = {0};
    Group.Mask = (KAFFINITY)(1ull << ProcInfo->Index);
    Group.Group = ProcInfo->Group;
    if (SetThreadGroupAffinity(GetCurrentThread(), &Group, NULL)) {
        return QUIC_STATUS_SUCCESS;
    }
    return HRESULT_FROM_WIN32(GetLastError());
}

#define QuicCompartmentIdGetCurrent() GetCurrentThreadCompartmentId()
#define QuicCompartmentIdSetCurrent(CompartmentId) \
    HRESULT_FROM_WIN32(SetCurrentThreadCompartmentId(CompartmentId))

#else

#define QuicSetCurrentThreadProcessorAffinity(ProcessorIndex) QUIC_STATUS_SUCCESS

#endif

//
// Test Interface for loading a self-signed certificate.
//

#ifdef QUIC_TEST_APIS

typedef struct QUIC_SEC_CONFIG_PARAMS {
    uint32_t Flags; // QUIC_SEC_CONFIG_FLAGS
    void* Certificate;
    const char* Principal;
    uint8_t Thumbprint[20];
} QUIC_SEC_CONFIG_PARAMS;

typedef enum QUIC_SELF_SIGN_CERT_TYPE {
    QUIC_SELF_SIGN_CERT_USER,
    QUIC_SELF_SIGN_CERT_MACHINE
} QUIC_SELF_SIGN_CERT_TYPE;

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_SEC_CONFIG_PARAMS*
QuicPlatGetSelfSignedCert(
    _In_ QUIC_SELF_SIGN_CERT_TYPE Type
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatFreeSelfSignedCert(
    _In_ QUIC_SEC_CONFIG_PARAMS* Params
    );

#endif // QUIC_TEST_APIS

#ifdef _M_X64
#define QUIC_CPUID(FunctionId, eax, ebx, ecx, edx) \
    int CpuInfo[4]; \
    CpuInfo[0] = eax; \
    CpuInfo[1] = ebx; \
    CpuInfo[2] = ecx; \
    CpuInfo[3] = edx; \
    __cpuid(CpuInfo, FunctionId);
#else
#define QUIC_CPUID(FunctionId, eax, ebx, ecx, dx)
#endif

#if defined(__cplusplus)
}
#endif
