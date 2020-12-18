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

#define IS_POWER_OF_TWO(x) (((x) != 0) && (((x) & ((x) - 1)) == 0))

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

#define QUIC_CONTAINING_RECORD(address, type, field) \
    ((type *)((uint8_t*)(address) - offsetof(type, field)))

typedef struct QUIC_LIST_ENTRY {
    struct QUIC_LIST_ENTRY* Flink;
    struct QUIC_LIST_ENTRY* Blink;
} QUIC_LIST_ENTRY;

typedef struct QUIC_SINGLE_LIST_ENTRY {
    struct QUIC_SINGLE_LIST_ENTRY* Next;
} QUIC_SINGLE_LIST_ENTRY;

#ifndef FORCEINLINE
#if (_MSC_VER >= 1200)
#define FORCEINLINE __forceinline
#else
#define FORCEINLINE __inline
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
#define QUIC_POOL_CIDPREFIX                 'F0cQ' // Qc0F - QUIC CID Prefix
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
#define QUIC_POOL_TLS_RESUMPTION            '02cQ' // Qc20 - QUIC Platform TLS Resumption Buffer
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
#define QUIC_POOL_DATAPATH_BINDING          'C2cQ' // Qc2C - QUIC Platform datapath binding
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
#define QUIC_POOL_TLS_RSA                   'F3cQ' // Qc3F - QUIC Platform NCrypt RSA Key

typedef enum QUIC_THREAD_FLAGS {
    QUIC_THREAD_FLAG_NONE               = 0x0000,
    QUIC_THREAD_FLAG_SET_IDEAL_PROC     = 0x0001,
    QUIC_THREAD_FLAG_SET_AFFINITIZE     = 0x0002,
    QUIC_THREAD_FLAG_HIGH_PRIORITY      = 0x0004
} QUIC_THREAD_FLAGS;

#ifdef DEFINE_ENUM_FLAG_OPERATORS
DEFINE_ENUM_FLAG_OPERATORS(QUIC_THREAD_FLAGS);
#endif

#ifdef _KERNEL_MODE
#define QUIC_PLATFORM_TYPE 1
#include <quic_platform_winkernel.h>
#elif _WIN32
#define QUIC_PLATFORM_TYPE 2
#include <quic_platform_winuser.h>
#elif QUIC_PLATFORM_LINUX
#define QUIC_PLATFORM_TYPE 3
#include <quic_platform_linux.h>
#else
#define QUIC_PLATFORM_TYPE 0xFF
#error "Unsupported Platform"
#endif

#define QuicListEntryValidate(Entry) \
    QUIC_DBG_ASSERT( \
        (((Entry->Flink)->Blink) == Entry) && \
        (((Entry->Blink)->Flink) == Entry))

FORCEINLINE
void
QuicListInitializeHead(
    _Out_ QUIC_LIST_ENTRY* ListHead
    )
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

_Must_inspect_result_
FORCEINLINE
BOOLEAN
QuicListIsEmpty(
    _In_ const QUIC_LIST_ENTRY* ListHead
    )
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE
void
QuicListInsertHead(
    _Inout_ QUIC_LIST_ENTRY* ListHead,
    _Out_ __drv_aliasesMem QUIC_LIST_ENTRY* Entry
    )
{
    QuicListEntryValidate(ListHead);
    QUIC_LIST_ENTRY* Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
}

FORCEINLINE
void
QuicListInsertTail(
    _Inout_ QUIC_LIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem QUIC_LIST_ENTRY* Entry
    )
{
    QuicListEntryValidate(ListHead);
    QUIC_LIST_ENTRY* Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
}

FORCEINLINE
QUIC_LIST_ENTRY*
QuicListRemoveHead(
    _Inout_ QUIC_LIST_ENTRY* ListHead
    )
{
    QuicListEntryValidate(ListHead);
    QUIC_LIST_ENTRY* Entry = ListHead->Flink; // cppcheck-suppress shadowFunction
    QUIC_LIST_ENTRY* Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}

FORCEINLINE
BOOLEAN
QuicListEntryRemove(
    _In_ QUIC_LIST_ENTRY* Entry
    )
{
    QuicListEntryValidate(Entry);
    QUIC_LIST_ENTRY* Flink = Entry->Flink;
    QUIC_LIST_ENTRY* Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return (BOOLEAN)(Flink == Blink);
}

inline
void
QuicListMoveItems(
    _Inout_ QUIC_LIST_ENTRY* Source,
    _Inout_ QUIC_LIST_ENTRY* Destination
    )
{
    //
    // If there are items, copy them.
    //
    if (!QuicListIsEmpty(Source)) {

        if (QuicListIsEmpty(Destination)) {

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
        QuicListInitializeHead(Source);
    }
}

FORCEINLINE
void
QuicListPushEntry(
    _Inout_ QUIC_SINGLE_LIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem QUIC_SINGLE_LIST_ENTRY* Entry
    )
{
    Entry->Next = ListHead->Next;
    ListHead->Next = Entry;
}

FORCEINLINE
QUIC_SINGLE_LIST_ENTRY*
QuicListPopEntry(
    _Inout_ QUIC_SINGLE_LIST_ENTRY* ListHead
    )
{
    QUIC_SINGLE_LIST_ENTRY* FirstEntry = ListHead->Next;
    if (FirstEntry != NULL) {
        ListHead->Next = FirstEntry->Next;
    }
    return FirstEntry;
}

#include "quic_hashtable.h"
#include "quic_toeplitz.h"

//
// Test Interface for loading a self-signed certificate.
//

#ifdef QUIC_TEST_APIS

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct QUIC_CREDENTIAL_CONFIG QUIC_CREDENTIAL_CONFIG;

typedef enum QUIC_SELF_SIGN_CERT_TYPE {
    QUIC_SELF_SIGN_CERT_USER,
    QUIC_SELF_SIGN_CERT_MACHINE
} QUIC_SELF_SIGN_CERT_TYPE;

_IRQL_requires_max_(PASSIVE_LEVEL)
const QUIC_CREDENTIAL_CONFIG*
QuicPlatGetSelfSignedCert(
    _In_ QUIC_SELF_SIGN_CERT_TYPE Type
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatFreeSelfSignedCert(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig
    );

#if defined(__cplusplus)
}
#endif

#endif // QUIC_TEST_APIS
