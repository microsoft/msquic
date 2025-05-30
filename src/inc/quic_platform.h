/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Platform definitions.

Supported Environments:

    Windows user mode
    Windows kernel mode
    Linux user mode

--*/

#pragma once

#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define IS_POWER_OF_TWO(x) (((x) != 0) && (((x) & ((x) - 1)) == 0))

#define CXPLAT_MAX(a,b) (((a) > (b)) ? (a) : (b))

#define CXPLAT_MIN(a,b) (((a) < (b)) ? (a) : (b))

//
// Time unit conversion.
//
#define NS_TO_US(x)     ((x) / 1000)
#define US_TO_NS(x)     ((x) * 1000)
#define NS100_TO_US(x)  ((x) / 10)
#define US_TO_NS100(x)  ((x) * 10)
#define MS_TO_NS100(x)  ((x)*10000)
#define NS100_TO_MS(x)  ((x)/10000)
#define US_TO_MS(x)     ((x) / 1000)
#define MS_TO_US(x)     ((x) * 1000)
#define US_TO_S(x)      ((x) / (1000 * 1000))
#define S_TO_US(x)      ((x) * 1000 * 1000)
#define S_TO_NS(x)      ((x) * 1000 * 1000 * 1000)
#define MS_TO_S(x)      ((x) / 1000)
#define S_TO_MS(x)      ((x) * 1000)

#define CXPLAT_CONTAINING_RECORD(address, type, field) \
    ((type *)((uint8_t*)(address) - offsetof(type, field)))

#define CXPLAT_STRUCT_SIZE_THRU_FIELD(Type, Field) \
    (offsetof(Type, Field) + sizeof(((Type*)0)->Field))

#define CXPLAT_STRUCT_HAS_FIELD(Type, Size, Field) \
    (Size >= CXPLAT_STRUCT_SIZE_THRU_FIELD(Type, Field))

typedef struct CXPLAT_LIST_ENTRY {
    struct CXPLAT_LIST_ENTRY* Flink;
    struct CXPLAT_LIST_ENTRY* Blink;
} CXPLAT_LIST_ENTRY;

typedef struct CXPLAT_SLIST_ENTRY {
    struct CXPLAT_SLIST_ENTRY* Next;
} CXPLAT_SLIST_ENTRY;

#ifndef FORCEINLINE
#if (_MSC_VER >= 1200)
#define FORCEINLINE __forceinline
#else
#define FORCEINLINE QUIC_INLINE
#endif
#endif

//
// Different pool tags used for marking allocations.
//

#define QUIC_POOL_GENERIC                   'CIUQ' // QUIC - Generic QUIC
#define QUIC_POOL_SILO                      '00cQ' // Qc00 - QUIC Silo
#define QUIC_POOL_CONN                      '10cQ' // Qc01 - QUIC connection
#define QUIC_POOL_TP                        '20cQ' // Qc02 - QUIC connection transport parameters
#define QUIC_POOL_STREAM                    '30cQ' // Qc03 - QUIC stream
#define QUIC_POOL_SBUF                      '40cQ' // Qc04 - QUIC stream buffer
#define QUIC_POOL_META                      '50cQ' // Qc05 - QUIC sent frame metadata
#define QUIC_POOL_DATA                      '60cQ' // Qc06 - QUIC datagram buffer
#define QUIC_POOL_TEST                      '70cQ' // Qc07 - QUIC test code
#define QUIC_POOL_PERF                      '80cQ' // Qc08 - QUIC perf code
#define QUIC_POOL_TOOL                      '90cQ' // Qc09 - QUIC tool code
#define QUIC_POOL_WORKER                    'A0cQ' // Qc0A - QUIC Worker
#define QUIC_POOL_LISTENER                  'B0cQ' // Qc0B - QUIC Listener
#define QUIC_POOL_CID                       'C0cQ' // Qc0C - QUIC CID
#define QUIC_POOL_CIDHASH                   'D0cQ' // Qc0D - QUIC CID Hash
#define QUIC_POOL_CIDLIST                   'E0cQ' // Qc0E - QUIC CID List Entry
#define QUIC_POOL__UNUSED_1_                'F0cQ' // Qc0F - UNUSED
#define QUIC_POOL_ALPN                      '01cQ' // Qc10 - QUIC ALPN
#define QUIC_POOL_RANGE                     '11cQ' // Qc11 - QUIC Range
#define QUIC_POOL_SENDBUF                   '21cQ' // Qc12 - QUIC Send Buffer
#define QUIC_POOL_RECVBUF                   '31cQ' // Qc13 - QUIC Recv Buffer
#define QUIC_POOL_TIMERWHEEL                '41cQ' // Qc14 - QUIC Timer Wheel
#define QUIC_POOL_REGISTRATION              '51cQ' // Qc15 - QUIC Registration
#define QUIC_POOL_CONFIG                    '61cQ' // Qc16 - QUIC configuration
#define QUIC_POOL_BINDING                   '71cQ' // Qc17 - QUIC Core binding
#define QUIC_POOL_API                       '81cQ' // Qc18 - QUIC API Table
#define QUIC_POOL_PERPROC                   '91cQ' // Qc19 - QUIC Per Proc Context
#define QUIC_POOL_PLATFORM_SENDCTX          'A1cQ' // Qc1A - QUIC Platform Send Context
#define QUIC_POOL_TLS_ACHCTX                'B1cQ' // Qc1B - QUIC Platform TLS ACH Context
#define QUIC_POOL_TLS_SNI                   'C1cQ' // Qc1C - QUIC Platform TLS SNI
#define QUIC_POOL_TLS_PRINCIPAL             'D1cQ' // Qc1D - QUIC Platform TLS Principal
#define QUIC_POOL_TLS_CTX                   'E1cQ' // Qc1E - QUIC Platform TLS Context
#define QUIC_POOL_TLS_TRANSPARAMS           'F1cQ' // Qc1F - QUIC Platform TLS Transport Parameters
#define QUIC_POOL_CUSTOM_THREAD             '02cQ' // Qc20 - QUIC Platform Customm Thread Context
#define QUIC_POOL_TLS_SECCONF               '12cQ' // Qc21 - QUIC Platform TLS Sec Config
#define QUIC_POOL_TLS_PACKETKEY             '22cQ' // Qc22 - QUIC Platform TLS Packet Key
#define QUIC_POOL_TLS_KEY                   '32cQ' // Qc23 - QUIC Platform TLS Key
#define QUIC_POOL_TLS_HP_KEY                '42cQ' // Qc24 - QUIC Platform TLS HP Key
#define QUIC_POOL_TLS_HASH                  '52cQ' // Qc25 - QUIC Platform TLS Hash
#define QUIC_POOL_TLS_EXTRAS                '62cQ' // Qc26 - QUIC Platform TLS Extra Data
#define QUIC_POOL_TMP_ALLOC                 '72cQ' // Qc27 - QUIC temporary alloc
#define QUIC_POOL_PLATFORM_TMP_ALLOC        '82cQ' // Qc28 - QUIC Platform temporary alloc
#define QUIC_POOL_PLATFORM_PROC             '92cQ' // Qc29 - QUIC Platform Processor info
#define QUIC_POOL_PLATFORM_GENERIC          'A2cQ' // Qc2A - QUIC Platform generic
#define QUIC_POOL_DATAPATH                  'B2cQ' // Qc2B - QUIC Platform datapath
#define QUIC_POOL_SOCKET                    'C2cQ' // Qc2C - QUIC Platform socket
#define QUIC_POOL_STORAGE                   'D2cQ' // Qc2D - QUIC Platform storage
#define QUIC_POOL_HASHTABLE                 'E2cQ' // Qc2E - QUIC Platform hashtable
#define QUIC_POOL_HASHTABLE_MEMBER          'F2cQ' // Qc2F - QUIC Platform hashtable member lists
#define QUIC_POOL_LOOKUP_HASHTABLE          '03cQ' // Qc30 - QUIC Lookup Hash Table
#define QUIC_POOL_REMOTE_HASH               '13cQ' // Qc31 - QUIC Remote Hash Entry
#define QUIC_POOL_SERVERNAME                '23cQ' // Qc32 - QUIC Server Name
#define QUIC_POOL_APP_RESUMPTION_DATA       '33cQ' // Qc33 - QUIC App Resumption Data
#define QUIC_POOL_INITIAL_TOKEN             '43cQ' // Qc34 - QUIC Initial Token
#define QUIC_POOL_CLOSE_REASON              '53cQ' // Qc35 - QUIC Close Reason
#define QUIC_POOL_SERVER_CRYPTO_TICKET      '63cQ' // Qc36 - QUIC Crypto Server Ticket Buffer
#define QUIC_POOL_CLIENT_CRYPTO_TICKET      '73cQ' // Qc37 - QUIC Crypto Client Ticket Buffer
#define QUIC_POOL_CRYPTO_RESUMPTION_TICKET  '83cQ' // Qc38 - QUIC Crypto Resumption Ticket
#define QUIC_POOL_TLS_BUFFER                '93cQ' // Qc39 - QUIC Tls Buffer
#define QUIC_POOL_SEND_REQUEST              'A3cQ' // Qc3A - QUIC Send Request
#define QUIC_POOL_API_CTX                   'B3cQ' // Qc3B - QUIC API Context
#define QUIC_POOL_STATELESS_CTX             'C3cQ' // Qc3C - QUIC Stateless Context
#define QUIC_POOL_OPER                      'D3cQ' // Qc3D - QUIC Operation
#define QUIC_POOL_EVENT                     'E3cQ' // Qc3E - QUIC Event
#define QUIC_POOL_TLS_PFX                   'F3cQ' // Qc3F - QUIC Platform PFX
#define QUIC_POOL_VERSION_SETTINGS          '04cQ' // Qc40 - QUIC App-supplied version settings
#define QUIC_POOL_DEFAULT_COMPAT_VER_LIST   '14cQ' // Qc41 - QUIC Default compatible versions list
#define QUIC_POOL_VERSION_INFO              '24cQ' // Qc42 - QUIC Version info
#define QUIC_POOL_PROCESS                   '34cQ' // Qc43 - QUIC Process
#define QUIC_POOL_TLS_TMP_TP                '44cQ' // Qc44 - QUIC Platform TLS Temporary TP storage
#define QUIC_POOL_PCP                       '54cQ' // Qc45 - QUIC PCP
#define QUIC_POOL_DATAPATH_ADDRESSES        '64cQ' // Qc46 - QUIC Datapath Addresses
#define QUIC_POOL_TLS_TICKET_KEY            '74cQ' // Qc47 - QUIC Platform TLS ticket key
#define QUIC_POOL_TLS_CIPHER_SUITE_STRING   '84cQ' // Qc48 - QUIC TLS cipher suite string
#define QUIC_POOL_PLATFORM_WORKER           '94cQ' // Qc49 - QUIC platform worker
#define QUIC_POOL_ROUTE_RESOLUTION_WORKER   'A4cQ' // Qc4A - QUIC route resolution worker
#define QUIC_POOL_ROUTE_RESOLUTION_OPER     'B4cQ' // Qc4B - QUIC route resolution operation
#define QUIC_POOL_EXECUTION_CONFIG          'C4cQ' // Qc4C - QUIC execution config
#define QUIC_POOL_APP_BUFFER_CHUNK          'D4cQ' // Qc4D - QUIC receive chunk for app buffers
#define QUIC_POOL_CONN_POOL_API_TABLE       'E4cQ' // Qc4E - QUIC Connection Pool API table
#define QUIC_POOL_DATAPATH_RSS_CONFIG       'F4cQ' // Qc4F - QUIC Datapath RSS configuration
#define QUIC_POOL_TLS_AUX_DATA              '05cQ' // Qc50 - QUIC TLS Backing Aux data
#define QUIC_POOL_TLS_RECORD_ENTRY          '15cQ' // Qc51 - QUIC TLS Backing Record storage 

typedef enum CXPLAT_THREAD_FLAGS {
    CXPLAT_THREAD_FLAG_NONE               = 0x0000,
    CXPLAT_THREAD_FLAG_SET_IDEAL_PROC     = 0x0001,
    CXPLAT_THREAD_FLAG_SET_AFFINITIZE     = 0x0002,
    CXPLAT_THREAD_FLAG_HIGH_PRIORITY      = 0x0004
} CXPLAT_THREAD_FLAGS;

#ifdef DEFINE_ENUM_FLAG_OPERATORS
DEFINE_ENUM_FLAG_OPERATORS(CXPLAT_THREAD_FLAGS);
#endif

#ifdef _KERNEL_MODE
#define CX_PLATFORM_TYPE 1
#include "quic_platform_winkernel.h"
#elif _WIN32
#define CX_PLATFORM_TYPE 2
#include "quic_platform_winuser.h"
#elif CX_PLATFORM_LINUX
#define CX_PLATFORM_TYPE 3
#define CX_PLATFORM_USES_TLS_BUILTIN_CERTIFICATE 1
#include "quic_platform_posix.h"
#elif CX_PLATFORM_DARWIN
#define CX_PLATFORM_TYPE 4
#include "quic_platform_posix.h"
#else
#define CX_PLATFORM_TYPE 0xFF
#error "Unsupported Platform"
#endif

#if defined(__cplusplus)
extern "C" {
#endif

//
// Library Initialization
//

//
// Called in main, DLLMain or DriverEntry.
//
PAGEDX
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSystemLoad(
    void
    );

//
// Called in main (exit), DLLMain or DriverUnload.
//
PAGEDX
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSystemUnload(
    void
    );

//
// Initializes the PAL library. Calls to this and
// CxPlatformUninitialize must be serialized and cannot overlap.
//
PAGEDX
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatInitialize(
    void
    );

//
// Uninitializes the PAL library. Calls to this and
// CxPlatformInitialize must be serialized and cannot overlap.
//
PAGEDX
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatUninitialize(
    void
    );

#if defined(__cplusplus)
}
#endif

//
// List Abstraction
//

#define QuicListEntryValidate(Entry) \
    CXPLAT_DBG_ASSERT( \
        (((Entry->Flink)->Blink) == Entry) && \
        (((Entry->Blink)->Flink) == Entry))

FORCEINLINE
void
CxPlatListInitializeHead(
    _Out_ CXPLAT_LIST_ENTRY* ListHead
    )
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

_Must_inspect_result_
FORCEINLINE
BOOLEAN
CxPlatListIsEmpty(
    _In_ const CXPLAT_LIST_ENTRY* ListHead
    )
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

_Must_inspect_result_
FORCEINLINE
BOOLEAN
CxPlatListIsEmptyNoFence(
    _In_ const CXPLAT_LIST_ENTRY* ListHead
    )
{
    return (BOOLEAN)(QuicReadPtrNoFence((void**)&ListHead->Flink) == ListHead);
}

FORCEINLINE
void
CxPlatListInsertHead(
    _Inout_ CXPLAT_LIST_ENTRY* ListHead,
    _Out_ __drv_aliasesMem CXPLAT_LIST_ENTRY* Entry
    )
{
    QuicListEntryValidate(ListHead);
    CXPLAT_LIST_ENTRY* Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
}

FORCEINLINE
void
CxPlatListInsertTail(
    _Inout_ CXPLAT_LIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem CXPLAT_LIST_ENTRY* Entry
    )
{
    QuicListEntryValidate(ListHead);
    CXPLAT_LIST_ENTRY* Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
}

FORCEINLINE
void
CxPlatListInsertAfter(
    _Inout_ CXPLAT_LIST_ENTRY* ListEntry,
    _Inout_ __drv_aliasesMem CXPLAT_LIST_ENTRY* NewEntry
    )
{
    QuicListEntryValidate(ListEntry);
    CXPLAT_LIST_ENTRY* Flink = ListEntry->Flink;
    ListEntry->Flink = NewEntry;
    NewEntry->Flink = Flink;
    NewEntry->Blink = ListEntry;
    Flink->Blink = NewEntry;
}

FORCEINLINE
CXPLAT_LIST_ENTRY*
CxPlatListRemoveHead(
    _Inout_ CXPLAT_LIST_ENTRY* ListHead
    )
{
    QuicListEntryValidate(ListHead);
    CXPLAT_LIST_ENTRY* Entry = ListHead->Flink; // cppcheck-suppress shadowFunction
    CXPLAT_LIST_ENTRY* Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}

FORCEINLINE
BOOLEAN
CxPlatListEntryRemove(
    _In_ CXPLAT_LIST_ENTRY* Entry
    )
{
    QuicListEntryValidate(Entry);
    CXPLAT_LIST_ENTRY* Flink = Entry->Flink;
    CXPLAT_LIST_ENTRY* Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return (BOOLEAN)(Flink == Blink);
}

QUIC_INLINE
void
CxPlatListMoveItems(
    _Inout_ CXPLAT_LIST_ENTRY* Source,
    _Inout_ CXPLAT_LIST_ENTRY* Destination
    )
{
    //
    // If there are items, copy them.
    //
    if (!CxPlatListIsEmpty(Source)) {

        if (CxPlatListIsEmpty(Destination)) {

            //
            // Copy the links of the Source.
            //
            Destination->Flink = Source->Flink;
            Destination->Blink = Source->Blink;

            //
            // Fix the item's links to point to new head.
            //
            Destination->Flink->Blink = Destination;
            Destination->Blink->Flink = Destination;

        } else {

            //
            // Fix Destination's current last item to point
            // to the first of Source.
            //
            Source->Flink->Blink = Destination->Blink;
            Destination->Blink->Flink = Source->Flink;

            //
            // Fix Destination's new last item to be the of Source's last item.
            //
            Source->Blink->Flink = Destination;
            Destination->Blink = Source->Blink;
        }

        //
        // Reset the Source to empty list.
        //
        CxPlatListInitializeHead(Source);
    }
}

FORCEINLINE
void
CxPlatListPushEntry(
    _Inout_ CXPLAT_SLIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem CXPLAT_SLIST_ENTRY* Entry
    )
{
    Entry->Next = ListHead->Next;
    ListHead->Next = Entry;
}

FORCEINLINE
CXPLAT_SLIST_ENTRY*
CxPlatListPopEntry(
    _Inout_ CXPLAT_SLIST_ENTRY* ListHead
    )
{
    CXPLAT_SLIST_ENTRY* FirstEntry = ListHead->Next;
    if (FirstEntry != NULL) {
        ListHead->Next = FirstEntry->Next;
    }
    return FirstEntry;
}

#include "quic_hashtable.h"
#include "quic_toeplitz.h"

#ifdef DEBUG
void
CxPlatSetAllocFailDenominator(
    _In_ int32_t Value
    );

int32_t
CxPlatGetAllocFailDenominator(
    );
#endif

#ifdef DEBUG
#define CxPlatIsRandomMemoryFailureEnabled() (CxPlatGetAllocFailDenominator() != 0)
#else
#define CxPlatIsRandomMemoryFailureEnabled() (FALSE)
#endif

//
// General purpose execution context abstraction layer. Used for driving worker
// loops.
//

typedef struct QUIC_EXECUTION QUIC_EXECUTION;
typedef struct QUIC_GLOBAL_EXECUTION_CONFIG QUIC_GLOBAL_EXECUTION_CONFIG;
typedef struct QUIC_EXECUTION_CONFIG QUIC_EXECUTION_CONFIG;
typedef struct CXPLAT_EXECUTION_CONTEXT CXPLAT_EXECUTION_CONTEXT;

typedef struct CXPLAT_EXECUTION_STATE {
    uint64_t TimeNow;               // in microseconds
    uint64_t LastWorkTime;          // in microseconds
    uint64_t LastPoolProcessTime;   // in microseconds
    uint32_t WaitTime;
    uint32_t NoWorkCount;
    CXPLAT_THREAD_ID ThreadID;
} CXPLAT_EXECUTION_STATE;

typedef struct CXPLAT_WORKER_POOL CXPLAT_WORKER_POOL;

#ifndef _KERNEL_MODE

//
// Worker pool API used for driving execution contexts
//

CXPLAT_WORKER_POOL*
CxPlatWorkerPoolCreate(
    _In_opt_ QUIC_GLOBAL_EXECUTION_CONFIG* Config
    );

_Success_(return != NULL)
CXPLAT_WORKER_POOL*
CxPlatWorkerPoolCreateExternal(
    _In_ uint32_t Count,
    _In_reads_(Count) QUIC_EXECUTION_CONFIG* Configs,
    _Out_writes_(Count) QUIC_EXECUTION** Executions
    );

void
CxPlatWorkerPoolDelete(
    _In_opt_ CXPLAT_WORKER_POOL* WorkerPool
    );

uint32_t
CxPlatWorkerPoolGetCount(
    _In_ CXPLAT_WORKER_POOL* WorkerPool
    );

BOOLEAN
CxPlatWorkerPoolAddRef(
    _In_ CXPLAT_WORKER_POOL* WorkerPool
    );

void
CxPlatWorkerPoolRelease(
    _In_ CXPLAT_WORKER_POOL* WorkerPool
    );

uint32_t
CxPlatWorkerPoolGetIdealProcessor(
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _In_ uint32_t Index // Into the worker pool
    );

CXPLAT_EVENTQ*
CxPlatWorkerPoolGetEventQ(
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _In_ uint16_t Index // Into the worker pool
    );

void
CxPlatWorkerPoolAddExecutionContext(
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _Inout_ CXPLAT_EXECUTION_CONTEXT* Context,
    _In_ uint16_t Index // Into the worker pool
    );

uint32_t
CxPlatWorkerPoolWorkerPoll(
    _In_ QUIC_EXECUTION* Execution
    );

//
// Supports more dynamic operations, but must be submitted to the platform worker
// to manage.
//
typedef struct CXPLAT_POOL_EX {
    CXPLAT_POOL Base;
    CXPLAT_LIST_ENTRY Link;
    void* Owner;
} CXPLAT_POOL_EX;

void
CxPlatAddDynamicPoolAllocator(
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _Inout_ CXPLAT_POOL_EX* Pool,
    _In_ uint16_t Index // Into the execution config processor array
    );

void
CxPlatRemoveDynamicPoolAllocator(
    _Inout_ CXPLAT_POOL_EX* Pool
    );

#endif // !_KERNEL_MODE

//
// Returns FALSE when it's time to cleanup.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
(*CXPLAT_EXECUTION_FN)(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    );

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
(*CXPLAT_EXECUTION_WAKE_FN)(
    _Inout_ CXPLAT_EXECUTION_CONTEXT* Context
    );

typedef struct CXPLAT_EXECUTION_CONTEXT {

    CXPLAT_SLIST_ENTRY Entry;
    void* Context;
    void* CxPlatContext;
    CXPLAT_EXECUTION_FN Callback;
    uint64_t NextTimeUs;
    volatile BOOLEAN Ready;

} CXPLAT_EXECUTION_CONTEXT;

#ifdef _KERNEL_MODE // Not supported on kernel mode
#define CxPlatWakeExecutionContext(Context) CXPLAT_FRE_ASSERT(FALSE)
#else
void
CxPlatWakeExecutionContext(
    _In_ CXPLAT_EXECUTION_CONTEXT* Context
    );
#endif

//
// Test Interface for loading a self-signed certificate.
//

#ifdef QUIC_TEST_APIS

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct QUIC_CREDENTIAL_CONFIG QUIC_CREDENTIAL_CONFIG;
typedef struct QUIC_CERTIFICATE_HASH QUIC_CERTIFICATE_HASH;
typedef struct QUIC_CERTIFICATE_HASH_STORE QUIC_CERTIFICATE_HASH_STORE;
typedef struct QUIC_CERTIFICATE_FILE QUIC_CERTIFICATE_FILE;
typedef struct QUIC_CERTIFICATE_FILE_PROTECTED QUIC_CERTIFICATE_FILE_PROTECTED;
typedef struct QUIC_CERTIFICATE_PKCS12 QUIC_CERTIFICATE_PKCS12;

typedef enum CXPLAT_SELF_SIGN_CERT_TYPE {
    CXPLAT_SELF_SIGN_CERT_USER,
    CXPLAT_SELF_SIGN_CERT_MACHINE,
    CXPLAT_SELF_SIGN_CA_CERT_USER,
    CXPLAT_SELF_SIGN_CA_CERT_MACHINE
} CXPLAT_SELF_SIGN_CERT_TYPE;

typedef enum CXPLAT_TEST_CERT_TYPE {
    CXPLAT_TEST_CERT_VALID_SERVER,
    CXPLAT_TEST_CERT_VALID_CLIENT,
    CXPLAT_TEST_CERT_EXPIRED_SERVER,
    CXPLAT_TEST_CERT_EXPIRED_CLIENT,
    CXPLAT_TEST_CERT_SELF_SIGNED_SERVER,
    CXPLAT_TEST_CERT_SELF_SIGNED_CLIENT,
    CXPLAT_TEST_CERT_CA_SERVER,
    CXPLAT_TEST_CERT_CA_CLIENT,
} CXPLAT_TEST_CERT_TYPE;

_IRQL_requires_max_(PASSIVE_LEVEL)
const char*
CxPlatGetSelfSignedCertCaCertificateFileName(
    _In_ BOOLEAN ClientCertificate
    );


_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_CREDENTIAL_CONFIG*
CxPlatGetSelfSignedCert(
    _In_ CXPLAT_SELF_SIGN_CERT_TYPE Type,
    _In_ BOOLEAN ClientCertificate,
    _In_z_ const char* CaCertificateFile
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return == TRUE)
BOOLEAN
CxPlatGetTestCertificate(
    _In_ CXPLAT_TEST_CERT_TYPE Type,
    _In_ CXPLAT_SELF_SIGN_CERT_TYPE StoreType,
    _In_ uint32_t CredType,
    _Out_ QUIC_CREDENTIAL_CONFIG* Params,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, _Out_)
    _When_(CredType != QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, _Reserved_)
        QUIC_CERTIFICATE_HASH* CertHash,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE, _Out_)
    _When_(CredType != QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE, _Reserved_)
        QUIC_CERTIFICATE_HASH_STORE* CertHashStore,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE, _Out_)
    _When_(CredType != QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE, _Reserved_)
        QUIC_CERTIFICATE_FILE* CertFile,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED, _Out_)
    _When_(CredType != QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED, _Reserved_)
        QUIC_CERTIFICATE_FILE_PROTECTED* CertFileProtected,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12, _Out_)
    _When_(CredType != QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12, _Reserved_)
        QUIC_CERTIFICATE_PKCS12* Pkcs12,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_NONE, _Out_z_bytecap_(100))
    _When_(CredType != QUIC_CREDENTIAL_TYPE_NONE, _Reserved_)
        char Principal[100]
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatFreeSelfSignedCert(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatFreeSelfSignedCertCaFile(
    _In_z_ const char* CaFile
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatFreeTestCert(
    _In_ QUIC_CREDENTIAL_CONFIG* Params
    );

#if defined(__cplusplus)
}
#endif

#endif // QUIC_TEST_APIS

#if defined(__cplusplus)
}
#endif
