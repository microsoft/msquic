/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Abstraction Layer main module.

Environment:

    Linux

--*/

#include "platform_internal.h"
#include "quic_platform.h"
#include "quic_platform_dispatch.h"
#include "quic_trace.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <syslog.h>
#ifdef QUIC_CLOG
#include "platform_linux.c.clog.h"
#endif

#define CXPLAT_MAX_LOG_MSG_LEN        1024 // Bytes

#ifdef CX_PLATFORM_DISPATCH_TABLE
CX_PLATFORM_DISPATCH* PlatDispatch = NULL;
#else
int RandomFd; // Used for reading random numbers.
#endif

static const char TpLibName[] = "libmsquic.lttng.so";

uint64_t CxPlatTotalMemory;

__attribute__((noinline, noreturn))
void
quic_bugcheck(
    void
    )
{
    //
    // We want to prevent this routine from being inlined so that we can
    // easily detect when our bugcheck conditions have occurred just by
    // looking at callstack. However, even after specifying inline attribute,
    // it is possible certain optimizations will cause inlining. asm technique
    // is the gcc documented way to prevent such optimizations.
    //
    asm("");

    //
    // abort() sends a SIGABRT signal and it triggers termination and coredump.
    //
    abort();
}

void
CxPlatSystemLoad(
    void
    )
{
    //
    // Following code is modified from coreclr.
    // https://github.com/dotnet/coreclr/blob/ed5dc831b09a0bfed76ddad684008bebc86ab2f0/src/pal/src/misc/tracepointprovider.cpp#L106
    //

    long ShouldLoad = 1;

    //
    // Check if loading the LTTng providers should be disabled.
    //
    char *DisableValue = getenv("QUIC_LTTng");
    if (DisableValue != NULL) {
        ShouldLoad = strtol(DisableValue, NULL, 10);
    }

    if (!ShouldLoad) {
        return;
    }

    //
    // Get the path to the currently executing shared object (libmsquic.so).
    //
    Dl_info Info;
    int Succeeded = dladdr((void *)CxPlatSystemLoad, &Info);
    if (!Succeeded) {
        return;
    }

    size_t PathLen = strlen(Info.dli_fname);

    //
    // Find the length of the full path without the shared object name, including the trailing slash.
    //
    int LastTrailingSlashLen = -1;
    for (int i = PathLen; i >= 0; i--) {
        if (Info.dli_fname[i] == '/') {
            LastTrailingSlashLen = i + 1;
            break;
        }
    }

    if (LastTrailingSlashLen == -1) {
        return;
    }

    size_t TpLibNameLen = strlen(TpLibName);
    size_t ProviderFullPathLength = TpLibNameLen + LastTrailingSlashLen + 1;

    char* ProviderFullPath = CXPLAT_ALLOC_PAGED(ProviderFullPathLength, QUIC_POOL_PLATFORM_TMP_ALLOC);
    if (ProviderFullPath == NULL) {
        return;
    }

    CxPlatCopyMemory(ProviderFullPath, Info.dli_fname, LastTrailingSlashLen);
    CxPlatCopyMemory(ProviderFullPath + LastTrailingSlashLen, TpLibName, TpLibNameLen);
    ProviderFullPath[LastTrailingSlashLen + TpLibNameLen] = '\0';

    //
    // Load the tracepoint provider.
    // It's OK if this fails - that just means that tracing dependencies aren't available.
    //
    dlopen(ProviderFullPath, RTLD_NOW | RTLD_GLOBAL);

    CXPLAT_FREE(ProviderFullPath, QUIC_POOL_PLATFORM_TMP_ALLOC);
}

void
CxPlatSystemUnload(
    void
    )
{
}

QUIC_STATUS
CxPlatInitialize(
    void
    )
{
#ifdef CX_PLATFORM_DISPATCH_TABLE
    CXPLAT_FRE_ASSERT(PlatDispatch != NULL);
#else
    RandomFd = open("/dev/urandom", O_RDONLY|O_CLOEXEC);
    if (RandomFd == -1) {
        return (QUIC_STATUS)errno;
    }
#endif

    CxPlatTotalMemory = 0x40000000; // TODO - Hard coded at 1 GB. Query real value.

    return QUIC_STATUS_SUCCESS;
}

void
CxPlatUninitialize(
    void
    )
{
#ifndef CX_PLATFORM_DISPATCH_TABLE
    close(RandomFd);
#endif
}

void*
CxPlatAlloc(
    _In_ size_t ByteCount,
    _In_ uint32_t Tag
    )
{
    UNREFERENCED_PARAMETER(Tag);
#ifdef CX_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->Alloc(ByteCount);
#else
#ifdef QUIC_RANDOM_ALLOC_FAIL
    uint8_t Rand; CxPlatRandom(sizeof(Rand), &Rand);
    return ((Rand % 100) == 1) ? NULL : malloc(ByteCount);
#else
    return malloc(ByteCount);
#endif // QUIC_RANDOM_ALLOC_FAIL
#endif // CX_PLATFORM_DISPATCH_TABLE
}

void
CxPlatFree(
    __drv_freesMem(Mem) _Frees_ptr_opt_ void* Mem,
    _In_ uint32_t Tag
    )
{
    UNREFERENCED_PARAMETER(Tag);
#ifdef CX_PLATFORM_DISPATCH_TABLE
    PlatDispatch->Free(Mem);
#else
    free(Mem);
#endif
}

void
CxPlatPoolInitialize(
    _In_ BOOLEAN IsPaged,
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
#ifdef CX_PLATFORM_DISPATCH_TABLE
    PlatDispatch->PoolInitialize(IsPaged, Size, Pool);
#else
    UNREFERENCED_PARAMETER(IsPaged);
    Pool->Size = Size;
    Pool->MemTag = Tag;
#endif
}

void
CxPlatPoolUninitialize(
    _Inout_ CXPLAT_POOL* Pool
    )
{
#ifdef CX_PLATFORM_DISPATCH_TABLE
    PlatDispatch->PoolUninitialize(Pool);
#else
    UNREFERENCED_PARAMETER(Pool);
#endif
}

void*
CxPlatPoolAlloc(
    _Inout_ CXPLAT_POOL* Pool
    )
{
#ifdef CX_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->PoolAlloc(Pool);
#else
    void*Entry = CxPlatAlloc(Pool->Size, Pool->MemTag);

    if (Entry != NULL) {
        CxPlatZeroMemory(Entry, Pool->Size);
    }

    return Entry;
#endif
}

void
CxPlatPoolFree(
    _Inout_ CXPLAT_POOL* Pool,
    _In_ void* Entry
    )
{
#ifdef CX_PLATFORM_DISPATCH_TABLE
    PlatDispatch->PoolFree(Pool, Entry);
#else
    UNREFERENCED_PARAMETER(Pool);
    CxPlatFree(Entry, Pool->MemTag);
#endif
}

void
CxPlatRefInitialize(
    _Inout_ CXPLAT_REF_COUNT* RefCount
    )
{
    *RefCount = 1;
}

void
CxPlatRefIncrement(
    _Inout_ CXPLAT_REF_COUNT* RefCount
    )
{
    if (__atomic_add_fetch(RefCount, 1, __ATOMIC_SEQ_CST)) {
        return;
    }

    CXPLAT_FRE_ASSERT(FALSE);
}

BOOLEAN
CxPlatRefIncrementNonZero(
    _Inout_ volatile CXPLAT_REF_COUNT* RefCount
    )
{
    CXPLAT_REF_COUNT OldValue = *RefCount;

    for (;;) {
        CXPLAT_REF_COUNT NewValue = OldValue + 1;

        if (NewValue > 1) {
            if(__atomic_compare_exchange_n(RefCount, &OldValue, NewValue, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
                return TRUE;
            }
            continue;
        }

        if (NewValue == 1) {
            return FALSE;
        }

        CXPLAT_FRE_ASSERT(false);
        return FALSE;
    }
}

BOOLEAN
CxPlatRefDecrement(
    _In_ CXPLAT_REF_COUNT* RefCount
    )
{
    CXPLAT_REF_COUNT NewValue = __atomic_sub_fetch(RefCount, 1, __ATOMIC_SEQ_CST);

    if (NewValue > 0) {
        return FALSE;
    }

    if (NewValue == 0) {
        return TRUE;
    }

    CXPLAT_FRE_ASSERT(FALSE);

    return FALSE;
}

void
CxPlatRundownInitialize(
    _Inout_ CXPLAT_RUNDOWN_REF* Rundown
    )
{
    CxPlatRefInitialize(&((Rundown)->RefCount));
    CxPlatEventInitialize(&((Rundown)->RundownComplete), false, false);
}

void
CxPlatRundownInitializeDisabled(
    _Inout_ CXPLAT_RUNDOWN_REF* Rundown
    )
{
    (Rundown)->RefCount = 0;
    CxPlatEventInitialize(&((Rundown)->RundownComplete), false, false);
}

void
CxPlatRundownReInitialize(
    _Inout_ CXPLAT_RUNDOWN_REF* Rundown
    )
{
    (Rundown)->RefCount = 1;
}

void
CxPlatRundownUninitialize(
    _Inout_ CXPLAT_RUNDOWN_REF* Rundown
    )
{
    CxPlatEventUninitialize((Rundown)->RundownComplete);
}

BOOLEAN
CxPlatRundownAcquire(
    _Inout_ CXPLAT_RUNDOWN_REF* Rundown
    )
{
    return CxPlatRefIncrementNonZero(&(Rundown)->RefCount);
}

void
CxPlatRundownRelease(
    _Inout_ CXPLAT_RUNDOWN_REF* Rundown
    )
{
    if (CxPlatRefDecrement(&(Rundown)->RefCount)) {
        CxPlatEventSet((Rundown)->RundownComplete);
    }
}

void
CxPlatRundownReleaseAndWait(
    _Inout_ CXPLAT_RUNDOWN_REF* Rundown
    )
{
    if (!CxPlatRefDecrement(&(Rundown)->RefCount)) {
        CxPlatEventWaitForever((Rundown)->RundownComplete);
    }
}

void
CxPlatEventInitialize(
    _Out_ CXPLAT_EVENT* Event,
    _In_ BOOLEAN ManualReset,
    _In_ BOOLEAN InitialState
    )
{
    CXPLAT_EVENT_OBJECT* EventObj = NULL;
    pthread_condattr_t Attr = {0};

    EventObj = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_EVENT_OBJECT), QUIC_POOL_EVENT);

    //
    // MsQuic expects this call to be non failable.
    //

    CXPLAT_DBG_ASSERT(EventObj != NULL);

    EventObj->AutoReset = !ManualReset;
    EventObj->Signaled = InitialState;

    CXPLAT_FRE_ASSERT(pthread_mutex_init(&EventObj->Mutex, NULL) == 0);
    CXPLAT_FRE_ASSERT(pthread_condattr_init(&Attr) == 0);
    CXPLAT_FRE_ASSERT(pthread_condattr_setclock(&Attr, CLOCK_MONOTONIC) == 0);
    CXPLAT_FRE_ASSERT(pthread_cond_init(&EventObj->Cond, &Attr) == 0);
    CXPLAT_FRE_ASSERT(pthread_condattr_destroy(&Attr) == 0);

    (*Event) = EventObj;
}

void
CxPlatEventUninitialize(
    _Inout_ CXPLAT_EVENT Event
    )
{
    CXPLAT_EVENT_OBJECT* EventObj = Event;

    CXPLAT_FRE_ASSERT(pthread_cond_destroy(&EventObj->Cond) == 0);
    CXPLAT_FRE_ASSERT(pthread_mutex_destroy(&EventObj->Mutex) == 0);

    CXPLAT_FREE(EventObj, QUIC_POOL_EVENT);
    EventObj = NULL;
}

void
CxPlatEventSet(
    _Inout_ CXPLAT_EVENT Event
    )
{
    CXPLAT_EVENT_OBJECT* EventObj = Event;

    CXPLAT_FRE_ASSERT(pthread_mutex_lock(&EventObj->Mutex) == 0);

    EventObj->Signaled = true;

    CXPLAT_FRE_ASSERT(pthread_mutex_unlock(&EventObj->Mutex) == 0);

    //
    // Signal the condition.
    //

    CXPLAT_FRE_ASSERT(pthread_cond_broadcast(&EventObj->Cond) == 0);
}

void
CxPlatEventReset(
    _Inout_ CXPLAT_EVENT Event
    )
{
    CXPLAT_EVENT_OBJECT* EventObj = Event;

    CXPLAT_FRE_ASSERT(pthread_mutex_lock(&EventObj->Mutex) == 0);
    EventObj->Signaled = false;
    CXPLAT_FRE_ASSERT(pthread_mutex_unlock(&EventObj->Mutex) == 0);
}

void
CxPlatEventWaitForever(
    _Inout_ CXPLAT_EVENT Event
    )
{
    CXPLAT_EVENT_OBJECT* EventObj = Event;

    CXPLAT_FRE_ASSERT(pthread_mutex_lock(&Event->Mutex) == 0);

    //
    // Spurious wake ups from pthread_cond_wait can occur. So the function needs
    // to be called in a loop until the predicate 'Signalled' is satisfied.
    //

    while (!EventObj->Signaled) {
        CXPLAT_FRE_ASSERT(pthread_cond_wait(&EventObj->Cond, &EventObj->Mutex) == 0);
    }

    if(EventObj->AutoReset) {
        EventObj->Signaled = false;
    }

    CXPLAT_FRE_ASSERT(pthread_mutex_unlock(&EventObj->Mutex) == 0);
}

BOOLEAN
CxPlatEventWaitWithTimeout(
    _Inout_ CXPLAT_EVENT Event,
    _In_ uint32_t TimeoutMs
    )
{
    CXPLAT_EVENT_OBJECT* EventObj = Event;
    BOOLEAN WaitSatisfied = FALSE;
    struct timespec Ts = {0};

    //
    // Get absolute time.
    //

    CxPlatGetAbsoluteTime(TimeoutMs, &Ts);

    CXPLAT_FRE_ASSERT(pthread_mutex_lock(&EventObj->Mutex) == 0);

    while (!EventObj->Signaled) {

        int Result = pthread_cond_timedwait(&EventObj->Cond, &EventObj->Mutex, &Ts);

        if (Result == ETIMEDOUT) {
            WaitSatisfied = FALSE;
            goto Exit;
        }

        CXPLAT_DBG_ASSERT(Result == 0);
        UNREFERENCED_PARAMETER(Result);
    }

    if (EventObj->AutoReset) {
        EventObj->Signaled = FALSE;
    }

    WaitSatisfied = TRUE;

Exit:

    CXPLAT_FRE_ASSERT(pthread_mutex_unlock(&EventObj->Mutex) == 0);

    return WaitSatisfied;
}

uint64_t
CxPlatTimespecToUs(
    _In_ const struct timespec *Time
    )
{
    return (Time->tv_sec * CXPLAT_MICROSEC_PER_SEC) + (Time->tv_nsec / CXPLAT_NANOSEC_PER_MICROSEC);
}

uint64_t
CxPlatGetTimerResolution(
    void
    )
{
    struct timespec Res = {0};
    int ErrorCode = clock_getres(CLOCK_MONOTONIC, &Res);
    CXPLAT_DBG_ASSERT(ErrorCode == 0);
    UNREFERENCED_PARAMETER(ErrorCode);
    return CxPlatTimespecToUs(&Res);
}

uint64_t
CxPlatTimeUs64(
    void
    )
{
    struct timespec CurrTime = {0};
    int ErrorCode = clock_gettime(CLOCK_MONOTONIC, &CurrTime);
    CXPLAT_DBG_ASSERT(ErrorCode == 0);
    UNREFERENCED_PARAMETER(ErrorCode);
    return CxPlatTimespecToUs(&CurrTime);
}

void
CxPlatGetAbsoluteTime(
    _In_ unsigned long DeltaMs,
    _Out_ struct timespec *Time
    )
{
    int ErrorCode = 0;

    CxPlatZeroMemory(Time, sizeof(struct timespec));

    ErrorCode = clock_gettime(CLOCK_MONOTONIC, Time);

    CXPLAT_DBG_ASSERT(ErrorCode == 0);
    UNREFERENCED_PARAMETER(ErrorCode);

    Time->tv_sec += (DeltaMs / CXPLAT_MS_PER_SECOND);
    Time->tv_nsec += ((DeltaMs % CXPLAT_MS_PER_SECOND) * CXPLAT_NANOSEC_PER_MS);

    if (Time->tv_nsec > CXPLAT_NANOSEC_PER_SEC)
    {
        Time->tv_sec += 1;
        Time->tv_nsec -= CXPLAT_NANOSEC_PER_SEC;
    }
}

void
CxPlatSleep(
    _In_ uint32_t DurationMs
    )
{
    int ErrorCode = 0;
    struct timespec TS = {
        .tv_sec = (DurationMs / CXPLAT_MS_PER_SECOND),
        .tv_nsec = (CXPLAT_NANOSEC_PER_MS * (DurationMs % CXPLAT_MS_PER_SECOND))
    };

    ErrorCode = nanosleep(&TS, &TS);
    CXPLAT_DBG_ASSERT(ErrorCode == 0);
    UNREFERENCED_PARAMETER(ErrorCode);
}

uint32_t
CxPlatProcMaxCount(
    void
    )
{
    return (uint32_t)sysconf(_SC_NPROCESSORS_ONLN);
}

uint32_t
CxPlatProcActiveCount(
    void
    )
{
    return (uint32_t)sysconf(_SC_NPROCESSORS_ONLN);
}

uint32_t
CxPlatProcCurrentNumber(
    void
    )
{
    return (uint32_t)sched_getcpu();
}

QUIC_STATUS
CxPlatRandom(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    )
{
#ifdef CX_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->Random(BufferLen, Buffer);
#else
    if (read(RandomFd, Buffer, BufferLen) == -1) {
        return (QUIC_STATUS)errno;
    }
    return QUIC_STATUS_SUCCESS;
#endif
}

void
CxPlatConvertToMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    )
{
    CXPLAT_DBG_ASSERT(!(InAddr == OutAddr));

    CxPlatZeroMemory(OutAddr, sizeof(QUIC_ADDR));

    if (InAddr->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET) {
        OutAddr->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
        OutAddr->Ipv6.sin6_port = InAddr->Ipv4.sin_port;
        memset(&(OutAddr->Ipv6.sin6_addr.s6_addr[10]), 0xff, 2);
        memcpy(&(OutAddr->Ipv6.sin6_addr.s6_addr[12]), &InAddr->Ipv4.sin_addr.s_addr, 4);
    } else {
        *OutAddr = *InAddr;
    }
}

void
CxPlatConvertFromMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    )
{
    CXPLAT_DBG_ASSERT(InAddr->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET6);

    if (IN6_IS_ADDR_V4MAPPED(&InAddr->Ipv6.sin6_addr)) {
        QUIC_ADDR TmpAddrS = {0};
        QUIC_ADDR* TmpAddr = &TmpAddrS;

        TmpAddr->Ipv4.sin_family = QUIC_ADDRESS_FAMILY_INET;
        TmpAddr->Ipv4.sin_port = InAddr->Ipv6.sin6_port;
        memcpy(&TmpAddr->Ipv4.sin_addr.s_addr, &InAddr->Ipv6.sin6_addr.s6_addr[12], 4);
        *OutAddr = *TmpAddr;
    } else if (OutAddr != InAddr) {
        *OutAddr = *InAddr;
    }
}

QUIC_STATUS
CxPlatThreadCreate(
    _In_ CXPLAT_THREAD_CONFIG* Config,
    _Out_ CXPLAT_THREAD* Thread
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    pthread_attr_t Attr;
    if (pthread_attr_init(&Attr)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            errno,
            "pthread_attr_init failed");
        return errno;
    }

#ifdef __GLIBC__
    if (Config->Flags & CXPLAT_THREAD_FLAG_SET_AFFINITIZE) {
        cpu_set_t CpuSet;
        CPU_ZERO(&CpuSet);
        CPU_SET(Config->IdealProcessor, &CpuSet);
        if (!pthread_attr_setaffinity_np(&Attr, sizeof(CpuSet), &CpuSet)) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "pthread_attr_setaffinity_np failed");
        }
    } else {
        // TODO - Set Linux equivalent of NUMA affinity.
    }
    // There is no way to set an ideal processor in Linux.
#endif

    if (Config->Flags & CXPLAT_THREAD_FLAG_HIGH_PRIORITY) {
        struct sched_param Params;
        Params.sched_priority = sched_get_priority_max(SCHED_FIFO);
        if (!pthread_attr_setschedparam(&Attr, &Params)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                errno,
                "pthread_attr_setschedparam failed");
        }
    }

#ifdef CXPLAT_USE_CUSTOM_THREAD_CONTEXT

    CXPLAT_THREAD_CUSTOM_CONTEXT* CustomContext =
        CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_THREAD_CUSTOM_CONTEXT), QUIC_POOL_CUSTOM_THREAD);
    if (CustomContext == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Custom thread context",
            sizeof(CXPLAT_THREAD_CUSTOM_CONTEXT));
    }
    CustomContext->Callback = Config->Callback;
    CustomContext->Context = Config->Context;

    if (pthread_create(Thread, &Attr, CxPlatThreadCustomStart, CustomContext)) {
        Status = errno;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "pthread_create failed");
        CXPLAT_FREE(CustomContext, QUIC_POOL_CUSTOM_THREAD);
    }

#else // CXPLAT_USE_CUSTOM_THREAD_CONTEXT

    if (pthread_create(Thread, &Attr, Config->Callback, Config->Context)) {
        Status = errno;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "pthread_create failed");
    }

#endif // !CXPLAT_USE_CUSTOM_THREAD_CONTEXT

#ifndef __GLIBC__
    if (Status == QUIC_STATUS_SUCCESS) {
        if (Config->Flags & CXPLAT_THREAD_FLAG_SET_AFFINITIZE) {
            cpu_set_t CpuSet;
            CPU_ZERO(&CpuSet);
            CPU_SET(Config->IdealProcessor, &CpuSet);
            if (!pthread_setaffinity_np(*Thread, sizeof(CpuSet), &CpuSet)) {
                QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "pthread_setaffinity_np failed");
            }
        } else {
            // TODO - Set Linux equivalent of NUMA affinity.
        }
    }
#endif

    pthread_attr_destroy(&Attr);

    return Status;
}

void
CxPlatThreadDelete(
    _Inout_ CXPLAT_THREAD* Thread
    )
{
    UNREFERENCED_PARAMETER(Thread);
}

void
CxPlatThreadWait(
    _Inout_ CXPLAT_THREAD* Thread
    )
{
    CXPLAT_DBG_ASSERT(pthread_equal(*Thread, pthread_self()) == 0);
    CXPLAT_FRE_ASSERT(pthread_join(*Thread, NULL) == 0);
}

uint32_t
CxPlatCurThreadID(
    void
    )
{
    CXPLAT_STATIC_ASSERT(sizeof(pid_t) <= sizeof(uint32_t), "PID size exceeds the expected size");
    return syscall(__NR_gettid);
}

void
CxPlatLogAssert(
    _In_z_ const char* File,
    _In_ int Line,
    _In_z_ const char* Expr
    )
{
    QuicTraceEvent(
        LibraryAssert,
        "[ lib] ASSERT, %u:%s - %s.",
        (uint32_t)Line,
        File,
        Expr);
}
