/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Abstraction Layer main module.

Environment:

    Linux

--*/

#include "../core/precomp.h"
#include "platform_internal.h"
#include "quic_platform.h"
#include <limits.h>
#include <sched.h>
#include <fcntl.h>
#include <syslog.h>
#include <arpa/inet.h>
#include "quic_trace.h"
#include "quic_platform_dispatch.h"

#define QUIC_MAX_LOG_MSG_LEN        1024 // Bytes

QUIC_PLATFORM_DISPATCH* PlatDispatch = NULL;
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
/*++

Routine Description:

    This function is called during msquic library init/load time.

Arguments:

    None

Return Value:

    None

--*/
{
    return;
}


void
QuicPlatformSystemUnload(
    void
    )
/*++

Routine Description:

    This function is called during msquic library un-init/unload time.

Arguments:

    None

Return Value:

    None

--*/
{
    return;
}


QUIC_STATUS
QuicPlatformInitialize(
    void
    )

{
    time_t t = {0};

    //
    // Seed the random number generator.
    //

    srand((unsigned) time(&t));

    QuicTotalMemory = 0x40000000; // TODO - Hard coded at 1 GB. Query real value.

    return QUIC_STATUS_SUCCESS;
}


void
QuicPlatformUninitialize(
    void
    )


{
    return;
}


void*
QuicAlloc(
    _In_ SIZE_T ByteCount
    )

{
    if (PlatDispatch != NULL) {
        return PlatDispatch->Alloc(ByteCount);
    }

    return malloc(ByteCount);
}


void
QuicFree(
    __drv_freesMem(Mem) _Frees_ptr_opt_ void* Mem
    )

{
    if (PlatDispatch != NULL) {
        PlatDispatch->Free(Mem);
        return;
    }

    free(Mem);
}


void
QuicPoolInitialize(
    _In_ BOOLEAN IsPaged,
    _In_ uint32_t Size,
    _Inout_ QUIC_POOL* Pool
    )

{
    if (PlatDispatch != NULL) {
        PlatDispatch->PoolInitialize(IsPaged, Size, Pool);
        return;
    }

    Pool->Size = Size;
}


void
QuicPoolUninitialize(
    _Inout_ QUIC_POOL* Pool
    )

{
    if (PlatDispatch != NULL) {
        PlatDispatch->PoolUninitialize(Pool);
        return;
    }
}


void*
QuicPoolAlloc(
    _Inout_ QUIC_POOL* Pool
    )

{
    void* Entry = NULL;

    if (PlatDispatch != NULL) {
        return PlatDispatch->PoolAlloc(Pool);
    }

    Entry = QuicAlloc(Pool->Size);

    if (Entry != NULL) {
        QuicZeroMemory(Entry, Pool->Size);
    }

    return Entry;
}


void
QuicPoolFree(
    _Inout_ QUIC_POOL* Pool,
    _In_ void* Entry
    )

{
    if (PlatDispatch != NULL) {
        PlatDispatch->PoolFree(Pool, Entry);
        return;
    }

    QuicFree(Entry);
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

    QUIC_FRE_ASSERT(EventObj != NULL);

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
    _In_ ULONG TimeoutMs
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

        QUIC_FRE_ASSERT(Result == 0);
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
    int ErrorCode = 0;
    struct timespec Res = {0};

    ErrorCode = clock_getres(CLOCK_MONOTONIC, &Res);

    QUIC_FRE_ASSERT(ErrorCode == 0);

    return QuicTimespecToUs(&Res);
}


uint64_t
QuicTimeUs64(
    void
    )

{
    int ErrorCode = 0;
    struct timespec CurrTime = {0};

    ErrorCode = clock_gettime(CLOCK_MONOTONIC, &CurrTime);

    QUIC_FRE_ASSERT(ErrorCode == 0);

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

    QUIC_FRE_ASSERT(ErrorCode == 0);

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
    QUIC_FRE_ASSERT(ErrorCode == 0);
}


uint32_t
QuicProcMaxCount(
    void
    )

{
    //
    // Linux_TODO: Currently hardcoded to 1. Remove this hack once Linux DAL
    // support multi proc model.
    //

    //long ProcCount = sysconf(_SC_NPROCESSORS_CONF);
    //QUIC_FRE_ASSERT(ProcCount > 0 && ProcCount <= UINT32_MAX);
    //return (uint32_t)ProcCount;

    return 1;
}


uint32_t
QuicProcActiveCount(
    void
    )

{
    //
    // Linux_TODO: Currently hardcoded to 1. Remove this hack once Linux DAL
    // support multi proc model.
    //

    //long ProcCount = sysconf(_SC_NPROCESSORS_ONLN);
    //QUIC_FRE_ASSERT(ProcCount > 0 && ProcCount <= UINT32_MAX);
    //return (uint32_t)ProcCount;

    return 1;
}


uint32_t
QuicProcCurrentNumber(
    void
    )

{
    //
    // Linux_TODO: Currently hardcoded to 0. Remove this hack once Linux DAL
    // support multi proc model.
    //

    //
    //int Cpu = sched_getcpu();
    //QUIC_FRE_ASSERT(Cpu >= 0);
    //return (uint32_t) Cpu;
    return 0;
}



QUIC_STATUS
QuicRandom(
    _In_ UINT32 BufferLen,
    _Out_writes_bytes_(BufferLen) PUCHAR Buffer
    )

{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (PlatDispatch != NULL) {
        Status = PlatDispatch->Random(BufferLen, Buffer);
        goto Exit;
    }

    for (uint32_t i = 0; i < BufferLen; i++) {
        Buffer[i] = (UCHAR)(rand() % 256);
    }

Exit:

    return Status;
}


void
QuicConvertToMappedV6(
    _In_ const SOCKADDR_INET * InAddr,
    _Out_ SOCKADDR_INET * OutAddr
    )

{
    QUIC_FRE_ASSERT(!(InAddr == OutAddr));

    QuicZeroMemory(OutAddr, sizeof(SOCKADDR_INET));

    if (InAddr->si_family == AF_INET) {
        OutAddr->Ipv6.sin6_family = AF_INET6;
        OutAddr->Ipv6.sin6_port = InAddr->Ipv4.sin_port;
        memset(&(OutAddr->Ipv6.sin6_addr.s6_addr[10]), 0xff, 2);
        memcpy(&(OutAddr->Ipv6.sin6_addr.s6_addr[12]), &InAddr->Ipv4.sin_addr.s_addr, 4);
    } else {
        *OutAddr = *InAddr;
    }
}


void
QuicConvertFromMappedV6(
    _In_ const SOCKADDR_INET * InAddr,
    _Out_ SOCKADDR_INET * OutAddr
    )

{
    QUIC_FRE_ASSERT(InAddr->si_family == AF_INET6);

    if (IN6_IS_ADDR_V4MAPPED(&InAddr->Ipv6.sin6_addr)) {
        SOCKADDR_INET TmpAddrS = {0};
        SOCKADDR_INET* TmpAddr = &TmpAddrS;

        TmpAddr->Ipv4.sin_family = AF_INET;
        TmpAddr->Ipv4.sin_port = InAddr->Ipv6.sin6_port;
        memcpy(&TmpAddr->Ipv4.sin_addr.s_addr, &InAddr->Ipv6.sin6_addr.s6_addr[12], 4);
        *OutAddr = *TmpAddr;
    } else if (OutAddr != InAddr) {
        *OutAddr = *InAddr;
    }
}


BOOLEAN
QuicAddrFamilyIsValid(
    _In_ QUIC_ADDRESS_FAMILY Family
    )

{
    return Family == AF_INET || Family == AF_INET6 || Family == AF_UNSPEC;
}


BOOLEAN
QuicAddrIsValid(
    _In_ const QUIC_ADDR * const Addr
    )

{
    QUIC_FRE_ASSERT(Addr);
    return QuicAddrFamilyIsValid(Addr->si_family);
}


BOOLEAN
QuicAddrCompareIp(
    _In_ const QUIC_ADDR * const Addr1,
    _In_ const QUIC_ADDR * const Addr2
    )

{
    QUIC_FRE_ASSERT(QuicAddrIsValid(Addr1));
    QUIC_FRE_ASSERT(QuicAddrIsValid(Addr2));

    if (AF_INET == Addr1->si_family) {
        return memcmp(&Addr1->Ipv4.sin_addr, &Addr2->Ipv4.sin_addr, sizeof(IN_ADDR)) == 0;
    } else {
        return memcmp(&Addr1->Ipv6.sin6_addr, &Addr2->Ipv6.sin6_addr, sizeof(IN6_ADDR)) == 0;
    }
}


BOOLEAN
QuicAddrCompare(
    _In_ const QUIC_ADDR * const Addr1,
    _In_ const QUIC_ADDR * const Addr2
    )

{
    QUIC_FRE_ASSERT(QuicAddrIsValid(Addr1));
    QUIC_FRE_ASSERT(QuicAddrIsValid(Addr2));

    if (Addr1->si_family != Addr2->si_family ||
        Addr1->Ipv4.sin_port != Addr2->Ipv4.sin_port) {
        return FALSE;
    }

    if (AF_INET == Addr1->si_family) {
        return memcmp(&Addr1->Ipv4.sin_addr, &Addr2->Ipv4.sin_addr, sizeof(IN_ADDR)) == 0;
    } else {
        return memcmp(&Addr1->Ipv6.sin6_addr, &Addr2->Ipv6.sin6_addr, sizeof(IN6_ADDR)) == 0;
    }
}


uint16_t
QuicAddrGetFamily(
    _In_ const QUIC_ADDR * const Addr
    )

{
    QUIC_FRE_ASSERT(QuicAddrIsValid(Addr));
    return Addr->si_family;
}


void
QuicAddrSetFamily(
    _In_ QUIC_ADDR * Addr,
    _In_ uint16_t Family
    )

{
    QUIC_FRE_ASSERT(Addr);
    QUIC_FRE_ASSERT(QuicAddrFamilyIsValid(Family));
    Addr->si_family = Family;
}


uint16_t
QuicAddrGetPort(
    _In_ const QUIC_ADDR * const Addr
    )

{
    QUIC_FRE_ASSERT(QuicAddrIsValid(Addr));

    if (AF_INET == Addr->si_family) {
        return ntohs(Addr->Ipv4.sin_port);
    } else {
        return ntohs(Addr->Ipv6.sin6_port);
    }
}


void
QuicAddrSetPort(
    _Out_ QUIC_ADDR * Addr,
    _In_ uint16_t Port
    )

{
    QUIC_FRE_ASSERT(QuicAddrIsValid(Addr));

    if (AF_INET == Addr->si_family) {
        Addr->Ipv4.sin_port = htons(Port);
    } else {
        Addr->Ipv6.sin6_port = htons(Port);
    }
}


BOOLEAN
QuicAddrIsBoundExplicitly(
    _In_ const QUIC_ADDR * const Addr
    )

{
    QUIC_FRE_ASSERT(QuicAddrIsValid(Addr));

    // LINUX_TODO: How to handle IPv4? Windows just does the below.

    //
    // Scope ID of zero indicates we are sending from a connected binding.
    //

    return Addr->Ipv6.sin6_scope_id == 0;
}


void
QuicAddrSetToLoopback(
    _Inout_ QUIC_ADDR * Addr
    )

{
    QUIC_FRE_ASSERT(QuicAddrIsValid(Addr));

    if (Addr->si_family == AF_INET) {
        Addr->Ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else {
        Addr->Ipv6.sin6_addr = in6addr_loopback;
    }
}

uint32_t
QuicAddrHash(
    _In_ const QUIC_ADDR * Addr
    )
{
    uint32_t Hash = 5387; // A random prime number.
#define UPDATE_HASH(byte) Hash = ((Hash << 5) - Hash) + (byte)
    if (Addr->si_family == AF_INET) {
        UPDATE_HASH(Addr->Ipv4.sin_port & 0xFF);
        UPDATE_HASH(Addr->Ipv4.sin_port >> 8);
        for (uint8_t i = 0; i < sizeof(Addr->Ipv4.sin_addr); ++i) {
            UPDATE_HASH(((uint8_t*)&Addr->Ipv4.sin_addr)[i]);
        }
    } else {
        UPDATE_HASH(Addr->Ipv6.sin6_port & 0xFF);
        UPDATE_HASH(Addr->Ipv6.sin6_port >> 8);
        for (uint8_t i = 0; i < sizeof(Addr->Ipv6.sin6_addr); ++i) {
            UPDATE_HASH(((uint8_t*)&Addr->Ipv6.sin6_addr)[i]);
        }
    }
    return Hash;
}


BOOLEAN
QuicAddrIsWildCard(
    _In_ const QUIC_ADDR * const Addr
    )
{
    if (Addr->si_family == AF_UNSPEC) {
        return TRUE;
    } else if (Addr->si_family == AF_INET) {
        const IN_ADDR ZeroAddr = {0};
        return memcmp(&Addr->Ipv4.sin_addr.s_addr, &ZeroAddr, sizeof(IN_ADDR)) == 0;
    } else {
        const IN6_ADDR ZeroAddr = {0};
        return memcmp(&Addr->Ipv6.sin6_addr, &ZeroAddr, sizeof(IN6_ADDR)) == 0;
    }
}


BOOLEAN
QuicAddr4FromString(
    _In_z_ const char* AddrStr,
    _Out_ QUIC_ADDR* Addr
    )
{
    if (AddrStr[0] == '[') {
        return FALSE;
    }
    char* PortStart = strchr(AddrStr, ':');
    if (PortStart != NULL) {
        if (strchr(PortStart+1, ':') != NULL) {
            return FALSE;
        }
        *PortStart = '\0';
        if (inet_pton(AF_INET, AddrStr, &Addr->Ipv4.sin_addr) != 1) {
            return FALSE;
        }
        *PortStart = ':';
        Addr->Ipv4.sin_port = htons(atoi(PortStart+1));
    } else {
        if (inet_pton(AF_INET, AddrStr, &Addr->Ipv4.sin_addr) != 1) {
            return FALSE;
        }
    }
    Addr->si_family = AF_INET;
    return TRUE;
}


BOOLEAN
QuicAddr6FromString(
    _In_z_ const char* AddrStr,
    _Out_ QUIC_ADDR* Addr
    )
{
    if (AddrStr[0] == '[') {
        char* BracketEnd = strchr(AddrStr, ']');
        if (BracketEnd == NULL || *(BracketEnd+1) != ':') {
            return FALSE;
        }
        *BracketEnd = '\0';
        if (inet_pton(AF_INET6, AddrStr+1, &Addr->Ipv6.sin6_addr) != 1) {
            return FALSE;
        }
        *BracketEnd = ']';
        Addr->Ipv6.sin6_port = htons(atoi(BracketEnd+2));
    } else {
        if (inet_pton(AF_INET6, AddrStr, &Addr->Ipv6.sin6_addr) != 1) {
            return FALSE;
        }
    }
    Addr->si_family = AF_INET6;
    return TRUE;
}


BOOLEAN
QuicAddrFromString(
    _In_z_ const char* AddrStr,
    _In_ uint16_t Port, // Host byte order
    _Out_ QUIC_ADDR* Addr
    )
{
    Addr->Ipv4.sin_port = htons(Port);
    return
        QuicAddr4FromString(AddrStr, Addr) ||
        QuicAddr6FromString(AddrStr, Addr);
}


BOOLEAN
QuicAddrToString(
    _In_ const QUIC_ADDR* Addr,
    _Out_ QUIC_ADDR_STR* AddrStr
    )
{
    char* Address = AddrStr->Address;
    if (Addr->si_family == AF_INET6 && Addr->Ipv6.sin6_port != 0) {
        Address[0] = '[';
        Address++;
    }
    if (inet_ntop(
            Addr->si_family,
            &Addr->Ipv4.sin_addr,
            Address,
            sizeof(QUIC_ADDR_STR)) != NULL) {
        return FALSE;
    }
    if (Addr->Ipv4.sin_port != 0) {
        Address += strlen(Address);
        if (Addr->si_family == AF_INET6) {
            Address[0] = ']';
            Address++;
        }
        sprintf(Address, ":%hu", ntohs(Addr->Ipv4.sin_port));
    }
    return TRUE;
}


int
_strnicmp(
    _In_ const char * _Str1,
    _In_ const char * _Str2,
    _In_ size_t _MaxCount
    )
{
    return strncasecmp(_Str1, _Str2, _MaxCount);
}


QUIC_STATUS
QuicThreadCreate(
    _In_ QUIC_THREAD_CONFIG* Config,
    _Out_ QUIC_THREAD** Thread
    )

{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_THREAD* ThreadObj = NULL;
    int Ret = 0;

    ThreadObj = QuicAlloc(sizeof(QUIC_THREAD));

    if (ThreadObj == NULL) {
        LogWarning("[qpal] Thread allocation failed.");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto exit;
    }

    Ret = pthread_create(&ThreadObj->Thread, NULL, Config->Callback, Config->Context);

    if (Ret != 0) {
        LogError("[qpal] pthread_create() failed.");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto exit;
    }

    *Thread = ThreadObj;

exit:

    return Status;
}


void
QuicThreadDelete(
    _Inout_ QUIC_THREAD* Thread
    )

{
    QuicFree(Thread);
}


void
QuicThreadWait(
    _Inout_ QUIC_THREAD* Thread
    )

{
    QUIC_FRE_ASSERT(pthread_equal(Thread->Thread, pthread_self()) == 0);

    QUIC_FRE_ASSERT(pthread_join(Thread->Thread, NULL) == 0);
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
    _In_z_ const char* Func,
    _In_z_ const char* Expr
    )

{
    LogError("[Assert] %s:%s:%d:%s", Expr, Func, Line, File);
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


void
QuicSysLogWrite(
    _In_ QUIC_TRACE_LEVEL Level,
    _In_ const char* Fmt,
    ...
    )

{
    va_list Args = {0};

    if (PlatDispatch != NULL) {
        va_start(Args, Fmt);
        PlatDispatch->Log(Level, Fmt, Args);
        va_end(Args);
        return;
    }

    char Buffer[QUIC_MAX_LOG_MSG_LEN] = {0};
    va_start(Args, Fmt);
    (void)vsnprintf(Buffer, sizeof(Buffer), Fmt, Args);
    va_end(Args);
    syslog(
        LOG_MAKEPRI(LOG_DAEMON, QuicLogLevelToPriority(Level)),
        "[%u][quic]%s", (uint32_t)syscall(__NR_gettid), Buffer);
}
