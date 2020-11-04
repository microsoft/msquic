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

#define QUIC_POOL_GENERIC                   'CIUQ'  // QUIC - Generic QUIC
#define QUIC_POOL_SILO                      'olsQ' // Qslo - QUIC Silo
#define QUIC_POOL_CONN                      'noCQ' // QCon - QUIC connection
#define QUIC_POOL_TP                        'PTCQ' // QCTP - QUIC connection transport parameters
#define QUIC_POOL_STREAM                    'mtSQ' // QStm - QUIC stream
#define QUIC_POOL_SBUF                      'fBSQ' // QSBf - QUIC stream buffer
#define QUIC_POOL_META                      'MFSQ' // QSFM - QUIC sent frame metadata
#define QUIC_POOL_DATA                      'atDQ' // QDta - QUIC datagram buffer
#define QUIC_POOL_TEST                      'tsTQ' // QTst - QUIC test code
#define QUIC_POOL_PERF                      'frPQ' // QPrf - QUIC perf code
#define QUIC_POOL_TOOL                      'loTQ' // QTol - QUIC tool code
#define QUIC_POOL_WORKER                    'rkwQ' // Qwkr - QUIC Worker
#define QUIC_POOL_LISTENER                  'rslQ' // Qlsr - QUIC Listener
#define QUIC_POOL_CID                       'DICQ' // QCID - QUIC CID
#define QUIC_POOL_CIDHASH                   'SHCQ' // QCHS - QUIC CID Hash
#define QUIC_POOL_CIDLIST                   'TLCQ' // QCLT - QUIC CID List Entry
#define QUIC_POOL_CIDPREFIX                 'xpCQ' // QCpx - QUIC CID Prefix
#define QUIC_POOL_ALPN                      'LPAQ' // QAPL - QUIC ALPN
#define QUIC_POOL_RANGE                     'gnrQ' // Qrng - QUIC Range
#define QUIC_POOL_SENDBUF                   'fbsQ' // Qsbf - QUIC Send Buffer
#define QUIC_POOL_RECVBUF                   'fbrQ' // Qsbf - QUIC Recv Buffer
#define QUIC_POOL_TIMERWHEEL                'hwtQ' // Qtwh - QUIC Timer Wheel
#define QUIC_POOL_REGISTRATION              'gerQ' // Qreg - QUIC Registration
#define QUIC_POOL_CONFIG                    'gfCQ' // QCfg - QUIC configuration
#define QUIC_POOL_BINDING                   'dbCQ' // QCbd - QUIC Core binding
#define QUIC_POOL_API                       'ipaQ' // Qapi - QUIC API Table
#define QUIC_POOL_PERPROC                   'cppQ' // Qppc - QUIC Per Proc Context
#define QUIC_POOL_PLATFORM_SENDCTX          'csPQ' // QPsc - QUIC Platform Send Context
#define QUIC_POOL_TLS_ACHCTX                'atPQ' // QPta - QUIC Platform TLS ACH Context
#define QUIC_POOL_TLS_SNI                   'ntPQ' // QPtn - QUIC Platform TLS SNI
#define QUIC_POOL_TLS_PRINCIPAL             'rtPQ' // QPtn - QUIC Platform TLS Principal
#define QUIC_POOL_TLS_CTX                   'ctPQ' // QPtc - QUIC Platform TLS Context
#define QUIC_POOL_TLS_TRANSPARAMS           'ttPQ' // QPtc - QUIC Platform TLS Transport Parameters
#define QUIC_POOL_TLS_RESUMPTION            'rtPQ' // QPtr - QUIC Platform TLS Resumption Buffer
#define QUIC_POOL_TLS_SECCONF               'stPQ' // QPts - QUIC Platform TLS Sec Config
#define QUIC_POOL_TLS_PACKETKEY             'ptPQ' // QPts - QUIC Platform TLS Packet Key
#define QUIC_POOL_TLS_EXTRAS                'xtPQ' // QPtx - QUIC Platform TLS Extra Data
#define QUIC_POOL_TMP_ALLOC                 'atCQ' // QCta - QUIC temporary alloc
#define QUIC_POOL_PLATFORM_TMP_ALLOC        'atPQ' // QPta - QUIC Platform temporary alloc
#define QUIC_POOL_PLATFORM_PROC             'cpPQ' // QPpc - QUIC Platform Processor info
#define QUIC_POOL_PLATFORM_GENERIC          'LTPQ' // QPLT - QUIC Platform generic
#define QUIC_POOL_DATAPATH                  'pdPQ' // QPdp - QUIC Platform datapath
#define QUIC_POOL_DATAPATH_BINDING          'dbPQ' // QDbd - QUIC Platform datapath binding
#define QUIC_POOL_STORAGE                   'tsPQ' // QPst - QUIC Platform storage
#define QUIC_POOL_HASHTABLE                 'thPQ' // QPht - QUIC Platform hashtable
#define QUIC_POOL_HASHTABLE_MEMBER          'lhPQ' // QPhl - QUIC Platform hashtable member lists
#define QUIC_POOL_LOOKUP_HASHTABLE          'thLQ' // QLht - QUIC Lookup Hash Table
#define QUIC_POOL_REMOTE_HASH               'shRQ' // QRsh - QUIC Remote Hash Entry
#define QUIC_POOL_SERVERNAME                'nvsQ' // Qsvn - QUIC Server Name
#define QUIC_POOL_APP_RESUMPTION_DATA       'draQ' // Qard - QUIC App Resumption Data
#define QUIC_POOL_INITIAL_TOKEN             'ktiQ' // Qitk - QUIC Initial Token
#define QUIC_POOL_CLOSE_REASON              'srcQ' // Qcrs - QUIC Close Reason
#define QUIC_POOL_SERVER_CRYPTO_TICKET      'ktsQ' // Qstk - QUIC Crypto Server Ticket Buffer
#define QUIC_POOL_CLIENT_CRYPTO_TICKET      'ktcQ' // Qctk - QUIC Crypto Client Ticket Buffer
#define QUIC_POOL_CRYPTO_RESUMPTION_TICKET  'ktrQ' // Qrtk - QUIC Crypto Resumption Ticket
#define QUIC_POOL_TLS_BUFFER                'fbtQ' // Qtbf - QUIC Tls Buffer
#define QUIC_POOL_SEND_REQUEST              'qrsQ' // Qsrq - QUIC Send Request
#define QUIC_POOL_API_CTX                   'xcaQ' // Qacx - QUIC API Context
#define QUIC_POOL_STATELESS_CTX             'xcsQ' // Qscx - QUIC Stateless Context
#define QUIC_POOL_OPER                      'rpoQ' // Qopr - QUIC Operation

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
    QUIC_LIST_ENTRY* Entry = ListHead->Flink;
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
