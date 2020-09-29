/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Abstraction Layer main module.

Environment:

    Linux

--*/

#define _GNU_SOURCE
#include "platform_internal.h"
#include "quic_platform.h"
#include <limits.h>
#include <sched.h>
#include <fcntl.h>
#include <syslog.h>
#include <dlfcn.h>
#include "quic_trace.h"
#include "quic_platform_dispatch.h"
#ifdef QUIC_CLOG
#include "platform_linux.c.clog.h"
#endif

#define QUIC_MAX_LOG_MSG_LEN        1024 // Bytes

#ifdef QUIC_PLATFORM_DISPATCH_TABLE
QUIC_PLATFORM_DISPATCH* PlatDispatch = NULL;
#else
int RandomFd; // Used for reading random numbers.
#endif

static const char TpLibName[] = "libmsquic.lttng.so";

uint64_t QuicTotalMemory;

__attribute__((noinline))
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
QuicPlatformSystemLoad(
    void
    )
{
    //
    // Following code is modified from coreclr.
    // https://github.com/dotnet/coreclr/blob/ed5dc831b09a0bfed76ddad684008bebc86ab2f0/src/pal/src/misc/tracepointprovider.cpp#L106
    //

    int ShouldLoad = 1;

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
    int Succeeded = dladdr((void *)QuicPlatformSystemLoad, &Info);
    if (!Succeeded) {
        return;
    }

    int PathLen = strlen(Info.dli_fname);

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

    char* ProviderFullPath = QUIC_ALLOC_PAGED(ProviderFullPathLength);
    if (ProviderFullPath == NULL) {
        return;
    }

    QuicCopyMemory(ProviderFullPath, Info.dli_fname, LastTrailingSlashLen);
    QuicCopyMemory(ProviderFullPath + LastTrailingSlashLen, TpLibName, TpLibNameLen);
    ProviderFullPath[LastTrailingSlashLen + TpLibNameLen] = '\0';

    //
    // Load the tracepoint provider.
    // It's OK if this fails - that just means that tracing dependencies aren't available.
    //
    dlopen(ProviderFullPath, RTLD_NOW | RTLD_GLOBAL);

    QUIC_FREE(ProviderFullPath);
}

void
QuicPlatformSystemUnload(
    void
    )
{
}

QUIC_STATUS
QuicPlatformInitialize(
    void
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    QUIC_FRE_ASSERT(PlatDispatch != NULL);
#else
    RandomFd = open("/dev/urandom", O_RDONLY);
    if (RandomFd == -1) {
        return (QUIC_STATUS)errno;
    }
#endif

    QuicTotalMemory = 0x40000000; // TODO - Hard coded at 1 GB. Query real value.

    return QUIC_STATUS_SUCCESS;
}

void
QuicPlatformUninitialize(
    void
    )
{
#ifndef QUIC_PLATFORM_DISPATCH_TABLE
    close(RandomFd);
#endif
}

void*
QuicAlloc(
    _In_ size_t ByteCount
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->Alloc(ByteCount);
#else
    return malloc(ByteCount);
#endif
}

void
QuicFree(
    __drv_freesMem(Mem) _Frees_ptr_opt_ void* Mem
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    PlatDispatch->Free(Mem);
#else
    free(Mem);
#endif
}

void
QuicPoolInitialize(
    _In_ BOOLEAN IsPaged,
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ QUIC_POOL* Pool
    )
{
    UNREFERENCED_PARAMETER(Tag);
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    PlatDispatch->PoolInitialize(IsPaged, Size, Pool);
#else
    UNREFERENCED_PARAMETER(IsPaged);
    Pool->Size = Size;
#endif
}

void
QuicPoolUninitialize(
    _Inout_ QUIC_POOL* Pool
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    PlatDispatch->PoolUninitialize(Pool);
#else
    UNREFERENCED_PARAMETER(Pool);
#endif
}

void*
QuicPoolAlloc(
    _Inout_ QUIC_POOL* Pool
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->PoolAlloc(Pool);
#else
    void*Entry = QuicAlloc(Pool->Size);

    if (Entry != NULL) {
        QuicZeroMemory(Entry, Pool->Size);
    }

    return Entry;
#endif
}

void
QuicPoolFree(
    _Inout_ QUIC_POOL* Pool,
    _In_ void* Entry
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    PlatDispatch->PoolFree(Pool, Entry);
#else
    UNREFERENCED_PARAMETER(Pool);
    QuicFree(Entry);
#endif
}

void
QuicRefInitialize(
    _Inout_ QUIC_REF_COUNT* RefCount
    )
{
    *RefCount = 1;
}

void
QuicRefIncrement(
    _Inout_ QUIC_REF_COUNT* RefCount
    )
{
    if (__atomic_add_fetch(RefCount, 1, __ATOMIC_SEQ_CST)) {
        return;
    }

    QUIC_FRE_ASSERT(FALSE);
}

BOOLEAN
QuicRefIncrementNonZero(
    _Inout_ volatile QUIC_REF_COUNT* RefCount
    )
{
    QUIC_REF_COUNT NewValue = 0;
    QUIC_REF_COUNT OldValue = *RefCount;

    for (;;) {
        NewValue = OldValue + 1;

        if ((QUIC_REF_COUNT)NewValue > 1) {
            if(__atomic_compare_exchange_n(RefCount, &OldValue, NewValue, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
                return TRUE;
            }
        } else if ((QUIC_REF_COUNT)NewValue == 1) {
            return FALSE;
        } else {
            QUIC_FRE_ASSERT(false);
            return FALSE;
        }
    }
}

BOOLEAN
QuicRefDecrement(
    _In_ QUIC_REF_COUNT* RefCount
    )
{
    QUIC_REF_COUNT NewValue = __atomic_sub_fetch(RefCount, 1, __ATOMIC_SEQ_CST);

    if (NewValue > 0) {
        return FALSE;
    } else if (NewValue == 0) {
        return TRUE;
    }

    QUIC_FRE_ASSERT(FALSE);

    return FALSE;
}

void
QuicRundownInitialize(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    )
{
    QuicRefInitialize(&((Rundown)->RefCount));
    QuicEventInitialize(&((Rundown)->RundownComplete), false, false);
}

void
QuicRundownInitializeDisabled(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    )
{
    (Rundown)->RefCount = 0;
    QuicEventInitialize(&((Rundown)->RundownComplete), false, false);
}

void
QuicRundownReInitialize(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    )
{
    (Rundown)->RefCount = 1;
}

void
QuicRundownUninitialize(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    )
{
    QuicEventUninitialize((Rundown)->RundownComplete);
}

BOOLEAN
QuicRundownAcquire(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    )
{
    return QuicRefIncrementNonZero(&(Rundown)->RefCount);
}

void
QuicRundownRelease(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    )
{
    if (QuicRefDecrement(&(Rundown)->RefCount)) {
        QuicEventSet((Rundown)->RundownComplete);
    }
}

void
QuicRundownReleaseAndWait(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    )
{
    if (!QuicRefDecrement(&(Rundown)->RefCount)) {
        QuicEventWaitForever((Rundown)->RundownComplete);
    }
}

void
QuicEventInitialize(
    _Out_ QUIC_EVENT* Event,
    _In_ BOOLEAN ManualReset,
    _In_ BOOLEAN InitialState
    )
{
    QUIC_EVENT_OBJECT* EventObj = NULL;
    pthread_condattr_t Attr = {0};

    //
    // LINUX_TODO: Tag allocation would be useful here.
    //

    EventObj = QuicAlloc(sizeof(QUIC_EVENT_OBJECT));

    //
    // MsQuic expects this call to be non failable.
    //

    QUIC_DBG_ASSERT(EventObj != NULL);

    EventObj->AutoReset = !ManualReset;
    EventObj->Signaled = InitialState;

    QUIC_FRE_ASSERT(pthread_mutex_init(&EventObj->Mutex, NULL) == 0);
    QUIC_FRE_ASSERT(pthread_condattr_init(&Attr) == 0);
    QUIC_FRE_ASSERT(pthread_condattr_setclock(&Attr, CLOCK_MONOTONIC) == 0);
    QUIC_FRE_ASSERT(pthread_cond_init(&EventObj->Cond, &Attr) == 0);
    QUIC_FRE_ASSERT(pthread_condattr_destroy(&Attr) == 0);

    (*Event) = EventObj;
}

void
QuicEventUninitialize(
    _Inout_ QUIC_EVENT Event
    )
{
    QUIC_EVENT_OBJECT* EventObj = Event;

    QUIC_FRE_ASSERT(pthread_cond_destroy(&EventObj->Cond) == 0);
    QUIC_FRE_ASSERT(pthread_mutex_destroy(&EventObj->Mutex) == 0);

    QuicFree(EventObj);
    EventObj = NULL;
}

void
QuicEventSet(
    _Inout_ QUIC_EVENT Event
    )
{
    QUIC_EVENT_OBJECT* EventObj = Event;

    QUIC_FRE_ASSERT(pthread_mutex_lock(&EventObj->Mutex) == 0);

    EventObj->Signaled = true;

    QUIC_FRE_ASSERT(pthread_mutex_unlock(&EventObj->Mutex) == 0);

    //
    // Signal the condition.
    //

    QUIC_FRE_ASSERT(pthread_cond_broadcast(&EventObj->Cond) == 0);
}

void
QuicEventReset(
    _Inout_ QUIC_EVENT Event
    )
{
    QUIC_EVENT_OBJECT* EventObj = Event;

    QUIC_FRE_ASSERT(pthread_mutex_lock(&EventObj->Mutex) == 0);
    EventObj->Signaled = false;
    QUIC_FRE_ASSERT(pthread_mutex_unlock(&EventObj->Mutex) == 0);
}

void
QuicEventWaitForever(
    _Inout_ QUIC_EVENT Event
    )
{
    QUIC_EVENT_OBJECT* EventObj = Event;

    QUIC_FRE_ASSERT(pthread_mutex_lock(&Event->Mutex) == 0);

    //
    // Spurious wake ups from pthread_cond_wait can occur. So the function needs
    // to be called in a loop until the predicate 'Signalled' is satisfied.
    //

    while (!EventObj->Signaled) {
        QUIC_FRE_ASSERT(pthread_cond_wait(&EventObj->Cond, &EventObj->Mutex) == 0);
    }

    if(EventObj->AutoReset) {
        EventObj->Signaled = false;
    }

    QUIC_FRE_ASSERT(pthread_mutex_unlock(&EventObj->Mutex) == 0);
}

BOOLEAN
QuicEventWaitWithTimeout(
    _Inout_ QUIC_EVENT Event,
    _In_ uint32_t TimeoutMs
    )
{
    QUIC_EVENT_OBJECT* EventObj = Event;
    BOOLEAN WaitSatisfied = FALSE;
    struct timespec Ts = {0};
    int Result = 0;

    //
    // Get absolute time.
    //

    QuicGetAbsoluteTime(TimeoutMs, &Ts);

    QUIC_FRE_ASSERT(pthread_mutex_lock(&EventObj->Mutex) == 0);

    while (!EventObj->Signaled) {

        Result = pthread_cond_timedwait(&EventObj->Cond, &EventObj->Mutex, &Ts);

        if (Result == ETIMEDOUT) {
            WaitSatisfied = FALSE;
            goto Exit;
        }

        QUIC_DBG_ASSERT(Result == 0);
        UNREFERENCED_PARAMETER(Result);
    }

    if (EventObj->AutoReset) {
        EventObj->Signaled = FALSE;
    }

    WaitSatisfied = TRUE;

Exit:

    QUIC_FRE_ASSERT(pthread_mutex_unlock(&EventObj->Mutex) == 0);

    return WaitSatisfied;
}

uint64_t
QuicTimespecToUs(
    _In_ const struct timespec *Time
    )
{
    return (Time->tv_sec * QUIC_MICROSEC_PER_SEC) + (Time->tv_nsec / QUIC_NANOSEC_PER_MICROSEC);
}

uint64_t
QuicGetTimerResolution(
    void
    )
{
    struct timespec Res = {0};
    int ErrorCode = clock_getres(CLOCK_MONOTONIC, &Res);
    QUIC_DBG_ASSERT(ErrorCode == 0);
    UNREFERENCED_PARAMETER(ErrorCode);
    return QuicTimespecToUs(&Res);
}

uint64_t
QuicTimeUs64(
    void
    )
{
    struct timespec CurrTime = {0};
    int ErrorCode = clock_gettime(CLOCK_MONOTONIC, &CurrTime);
    QUIC_DBG_ASSERT(ErrorCode == 0);
    UNREFERENCED_PARAMETER(ErrorCode);
    return QuicTimespecToUs(&CurrTime);
}

void
QuicGetAbsoluteTime(
    _In_ unsigned long DeltaMs,
    _Out_ struct timespec *Time
    )
{
    int ErrorCode = 0;

    QuicZeroMemory(Time, sizeof(struct timespec));

    ErrorCode = clock_gettime(CLOCK_MONOTONIC, Time);

    QUIC_DBG_ASSERT(ErrorCode == 0);
    UNREFERENCED_PARAMETER(ErrorCode);

    Time->tv_sec += (DeltaMs / QUIC_MS_PER_SECOND);
    Time->tv_nsec += ((DeltaMs % QUIC_MS_PER_SECOND) * QUIC_NANOSEC_PER_MS);

    if (Time->tv_nsec > QUIC_NANOSEC_PER_SEC)
    {
        Time->tv_sec += 1;
        Time->tv_nsec -= QUIC_NANOSEC_PER_SEC;
    }
}

void
QuicSleep(
    _In_ uint32_t DurationMs
    )
{
    int ErrorCode = 0;
    struct timespec TS = {
        .tv_sec = (DurationMs / QUIC_MS_PER_SECOND),
        .tv_nsec = (QUIC_NANOSEC_PER_MS * (DurationMs % QUIC_MS_PER_SECOND))
    };

    ErrorCode = nanosleep(&TS, &TS);
    QUIC_DBG_ASSERT(ErrorCode == 0);
    UNREFERENCED_PARAMETER(ErrorCode);
}

uint32_t
QuicProcMaxCount(
    void
    )
{
    return (uint32_t)sysconf(_SC_NPROCESSORS_ONLN);
}

uint32_t
QuicProcActiveCount(
    void
    )
{
    return (uint32_t)sysconf(_SC_NPROCESSORS_ONLN);
}

uint32_t
QuicProcCurrentNumber(
    void
    )
{
    return (uint32_t)sched_getcpu();
}

QUIC_STATUS
QuicRandom(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->Random(BufferLen, Buffer);
#else
    if (read(RandomFd, Buffer, BufferLen) == -1) {
        return (QUIC_STATUS)errno;
    }
    return QUIC_STATUS_SUCCESS;
#endif
}

void
QuicConvertToMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    )
{
    QUIC_DBG_ASSERT(!(InAddr == OutAddr));

    QuicZeroMemory(OutAddr, sizeof(QUIC_ADDR));

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
QuicConvertFromMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    )
{
    QUIC_DBG_ASSERT(InAddr->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET6);

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
QuicThreadCreate(
    _In_ QUIC_THREAD_CONFIG* Config,
    _Out_ QUIC_THREAD* Thread
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
    if (Config->Flags & QUIC_THREAD_FLAG_SET_AFFINITIZE) {
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

    if (Config->Flags & QUIC_THREAD_FLAG_HIGH_PRIORITY) {
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

    if (pthread_create(Thread, &Attr, Config->Callback, Config->Context)) {
        Status = errno;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "pthread_create failed");
    }

#ifndef __GLIBC__
    if (Status == QUIC_STATUS_SUCCESS) {
        if (Config->Flags & QUIC_THREAD_FLAG_SET_AFFINITIZE) {
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
QuicThreadDelete(
    _Inout_ QUIC_THREAD* Thread
    )
{
    UNREFERENCED_PARAMETER(Thread);
}

void
QuicThreadWait(
    _Inout_ QUIC_THREAD* Thread
    )
{
    QUIC_DBG_ASSERT(pthread_equal(*Thread, pthread_self()) == 0);
    QUIC_FRE_ASSERT(pthread_join(*Thread, NULL) == 0);
}

uint32_t
QuicCurThreadID(
    void
    )
{
    QUIC_STATIC_ASSERT(sizeof(pid_t) <= sizeof(uint32_t), "PID size exceeds the expected size");
    return syscall(__NR_gettid);
}

void
QuicPlatformLogAssert(
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

int
QuicLogLevelToPriority(
    _In_ QUIC_TRACE_LEVEL Level
    )
{
    //
    // LINUX_TODO: Re-evaluate these mappings.
    //

    switch(Level) {
        case QUIC_TRACE_LEVEL_DEV:
            return LOG_DEBUG;
        case QUIC_TRACE_LEVEL_VERBOSE:
            return LOG_DEBUG;
        case QUIC_TRACE_LEVEL_INFO:
            return LOG_INFO;
        case QUIC_TRACE_LEVEL_WARNING:
            return LOG_WARNING;
        case QUIC_TRACE_LEVEL_ERROR:
            return LOG_ERR;
        case QUIC_TRACE_LEVEL_PACKET_VERBOSE:
            return LOG_DEBUG;
        case QUIC_TRACE_LEVEL_PACKET_INFO:
            return LOG_INFO;
        case QUIC_TRACE_LEVEL_PACKET_WARNING:
            return LOG_WARNING;
        default:
            return LOG_DEBUG;
    }

    return LOG_DEBUG;
}
