/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC XDP Datapath Implementation (User Mode)

--*/

#define _CRT_SECURE_NO_WARNINGS 1 // TODO - Remove

#include "datapath_raw.h"
#ifdef QUIC_CLOG
#include "datapath_raw_xdp.c.clog.h"
#endif

#include <wbemidl.h>
#include <afxdp_helper.h>
#include <xdpapi.h>
#include <stdio.h>

#define RX_BATCH_SIZE 16
#define MAX_ETH_FRAME_SIZE 1514

#define QUEUE_TAG     'QpdX' // XdpQ
#define RX_BUFFER_TAG 'RpdX' // XdpR
#define TX_BUFFER_TAG 'TpdX' // XdpT

typedef struct _XDP_QUEUE {
    uint8_t* RxBuffers;
    HANDLE RxXsk;
    XSK_RING RxFillRing;
    XSK_RING RxRing;
    HANDLE RxProgram;
    uint8_t* TxBuffers;
    HANDLE TxXsk;
    XSK_RING TxRing;
    XSK_RING TxCompletionRing;
    BOOL Error;

    CXPLAT_LIST_ENTRY WorkerTxQueue;
    CXPLAT_SLIST_ENTRY WorkerRxPool;

    // Move contended buffer pools to their own cache lines.
    // TODO: Use better (more scalable) buffer algorithms.
    DECLSPEC_CACHEALIGN SLIST_HEADER RxPool;
    DECLSPEC_CACHEALIGN SLIST_HEADER TxPool;

    // Move TX queue to its own cache line.
    DECLSPEC_CACHEALIGN
    CXPLAT_LOCK TxLock;
    CXPLAT_LIST_ENTRY TxQueue;
} XDP_QUEUE;

typedef struct XDP_DATAPATH {
    CXPLAT_DATAPATH;

    BOOLEAN Running;
    CXPLAT_THREAD WorkerThread;
    CXPLAT_THREAD ExtraWorkerThreads[64];
    XDP_QUEUE* Queues;

    // Constants
    DECLSPEC_CACHEALIGN
    uint16_t IfIndex;
    uint16_t DatapathCpuGroup;
    uint8_t DatapathCpuNumber;
    uint32_t RxBufferCount;
    uint32_t RxRingSize;
    uint32_t TxBufferCount;
    uint32_t TxRingSize;
    uint32_t QueueCount;
    uint32_t ExtraThreads;
    BOOL Affinitize;
    BOOL TxAlwaysPoke;
} XDP_DATAPATH;

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) XDP_RX_PACKET {
    CXPLAT_RECV_DATA;
    CXPLAT_ROUTE RouteStorage;
    XDP_QUEUE* Queue;
    // Followed by:
    // uint8_t ClientContext[...];
    // uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_RX_PACKET;

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) XDP_TX_PACKET {
    CXPLAT_SEND_DATA;
    XDP_QUEUE* Queue;
    CXPLAT_LIST_ENTRY Link;
    uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_TX_PACKET;

CXPLAT_RECV_DATA*
CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET* const Context
    )
{
    return (CXPLAT_RECV_DATA*)(((uint8_t*)Context) - sizeof(XDP_RX_PACKET));
}

CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const Datagram
    )
{
    return (CXPLAT_RECV_PACKET*)(((uint8_t*)Datagram) + sizeof(XDP_RX_PACKET));
}

CXPLAT_THREAD_CALLBACK(CxPlatXdpWorkerThread, Context);
CXPLAT_THREAD_CALLBACK(CxPlatXdpExtraWorkerThread, Context);

QUIC_STATUS
CxPlatGetInterfaceRssQueueCount(
    _In_ uint32_t InterfaceIndex,
    _Out_ uint32_t* Count
    )
{
    HRESULT hRes;
    IWbemLocator *pLoc = NULL;
    IEnumWbemClassObject *pEnum = NULL;
    IWbemServices *pSvc = NULL;
    DWORD ret = 0;
    UINT32 cnt = 0;
    NET_LUID if_luid = { 0 };
    WCHAR if_alias[256 + 1] = { 0 };

    ret = ConvertInterfaceIndexToLuid(InterfaceIndex, &if_luid);
    if (ret != NO_ERROR) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "ConvertInterfaceIndexToLuid");
        return HRESULT_FROM_WIN32(ret);
    }

    ret = ConvertInterfaceLuidToAlias(&if_luid, if_alias, RTL_NUMBER_OF(if_alias));
    if (ret != NO_ERROR) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "ConvertInterfaceLuidToAlias");
        return HRESULT_FROM_WIN32(ret);
    }

    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------
    hRes =  CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hRes)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hRes,
            "CoInitializeEx");
        return hRes;
    }

    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------
    hRes = CoCreateInstance(
        &CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator, (LPVOID *) &pLoc);
    if (FAILED(hRes)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hRes,
            "CoCreateInstance IWbemLocator");
        goto Cleanup;
    }

    // Step 4: -----------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method
    // Connect to the root\cimv2 namespace with
    // the current user and obtain pointer pSvc
    // to make IWbemServices calls.
    BSTR Namespace = SysAllocString(L"ROOT\\STANDARDCIMV2");
    hRes = pLoc->lpVtbl->ConnectServer(pLoc,
         Namespace,               // Object path of WMI namespace
         NULL,                    // User name. NULL = current user
         NULL,                    // User password. NULL = current
         0,                       // Locale. NULL indicates current
         0,                       // Security flags.
         0,                       // Authority (for example, Kerberos)
         0,                       // Context object
         &pSvc                    // pointer to IWbemServices proxy
         );
    SysFreeString(Namespace);
    if (FAILED(hRes)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hRes,
            "ConnectServer");
        goto Cleanup;
    }

    // Step 5: --------------------------------------------------
    // Set security levels on the proxy -------------------------
    hRes = CoSetProxyBlanket(
       (IUnknown*)pSvc,             // Indicates the proxy to set
       RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
       RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
       NULL,                        // Server principal name
       RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
       RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
       NULL,                        // client identity
       EOAC_NONE                    // proxy capabilities
    );
    if (FAILED(hRes)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hRes,
            "CoSetProxyBlanket");
        goto Cleanup;
    }

    // Step 6: --------------------------------------------------
    // Use the IWbemServices pointer to make requests of WMI ----
    wchar_t query[512] = { '\0' };
    (void)wcscat_s(query, 512, L"SELECT * FROM MSFT_NetAdapterRssSettingData WHERE Name='");
    (void)wcscat_s(query, 512, if_alias);
    (void)wcscat_s(query, 512, L"'");
    //AF_XDP_LOG(INFO, "WMI query = \"%ws\"\n", query);

    BSTR Language = SysAllocString(L"WQL");
    BSTR Query = SysAllocString(query);
    hRes = pSvc->lpVtbl->ExecQuery(pSvc,
        Language,
        Query,
        WBEM_FLAG_FORWARD_ONLY,         // Flags
        0,                              // Context
        &pEnum
        );
    SysFreeString(Query);
    SysFreeString(Language);
    if (FAILED(hRes)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hRes,
            "ExecQuery");
        goto Cleanup;
    }

    // Step 7: -------------------------------------------------
    // Get the data from the query in step 6 -------------------
    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;
    while (pEnum) {
        HRESULT hr = pEnum->lpVtbl->Next(pEnum, WBEM_INFINITE, 1,
            &pclsObj, &uReturn);

        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;

        // Get the value of the IndirectionTable property
        hr = pclsObj->lpVtbl->Get(pclsObj, L"IndirectionTable", 0, &vtProp, 0, 0);
        if ((vtProp.vt == VT_NULL) || (vtProp.vt == VT_EMPTY)) {
            //AF_XDP_LOG(INFO, "No RSS indirection table, assuming 1 default queue\n");
            cnt++;
        } else if ((vtProp.vt & VT_ARRAY) == 0) {
            //AF_XDP_LOG(ERR, "not ARRAY\n");
        } else {
            long lLower, lUpper;
            SAFEARRAY *pSafeArray = vtProp.parray;
            UINT8 *rssIndicesBitset = NULL;
            DWORD rssIndicesBitsetBytes;
            DWORD numberOfProcs;

            SafeArrayGetLBound(pSafeArray, 1, &lLower);
            SafeArrayGetUBound(pSafeArray, 1, &lUpper);

            IUnknown** rawArray;
            SafeArrayAccessData(pSafeArray, (void**)&rawArray);

            // Set up the RSS bitset according to number of processors
            numberOfProcs = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
            rssIndicesBitsetBytes = (numberOfProcs / 8) + 1;
            rssIndicesBitset = malloc(rssIndicesBitsetBytes);
            memset(rssIndicesBitset, 0, rssIndicesBitsetBytes);

            for (long i = lLower; i <= lUpper; i++)
            {
                IUnknown* pIUnk = rawArray[i];
                IWbemClassObject *obj = NULL;
                pIUnk->lpVtbl->QueryInterface(pIUnk, &IID_IWbemClassObject, (void **)&obj);
                if (obj == NULL) {
                    QuicTraceEvent(
                        LibraryErrorStatus,
                        "[ lib] ERROR, %u, %s.",
                        hRes,
                        "QueryInterface");
                    //AF_XDP_LOG(ERR, "QueryInterface failed\n");
                    free(rssIndicesBitset);
                    goto Cleanup;
                }

                hr = obj->lpVtbl->Get(obj, L"ProcessorNumber", 0, &vtProp, 0, 0);
                UINT32 index = vtProp.iVal / (sizeof(rssIndicesBitset[0])*8);
                UINT32 offset = vtProp.iVal % (sizeof(rssIndicesBitset[0])*8);
                rssIndicesBitset[index] |= 1 << offset;

                VariantClear(&vtProp);
                obj->lpVtbl->Release(obj);
            }

            SafeArrayUnaccessData(pSafeArray);

            for (DWORD i = 0; i < numberOfProcs/(sizeof(rssIndicesBitset[0])*8) + 1; i++) {
                for (SIZE_T j = 0; j < sizeof(rssIndicesBitset[0])*8; j++) {
                    if (rssIndicesBitset[i] & (1 << j)) {
                        //AF_XDP_LOG(INFO, "detected active RSS queue %u on proc index %llu\n", cnt, (i*8 + j));
                        cnt++;
                    }
                }
            }

            free(rssIndicesBitset);
        }

        VariantClear(&vtProp);
        pclsObj->lpVtbl->Release(pclsObj);
    }

    //AF_XDP_LOG(INFO, "counted %u active queues on %s\n", cnt, if_name);
    *Count = cnt;

Cleanup:

    if (pEnum != NULL) {
        pEnum->lpVtbl->Release(pEnum);
    }
    if (pSvc != NULL) {
        pSvc->lpVtbl->Release(pSvc);
    }
    if (pLoc != NULL) {
        pLoc->lpVtbl->Release(pLoc);
    }
    CoUninitialize();

    return hRes;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatXdpReadConfig(
    _Inout_ XDP_DATAPATH* Xdp
    )
{
    // Default config
    Xdp->IfIndex = IFI_UNSPECIFIED;
    Xdp->QueueCount = 1;
    Xdp->RxBufferCount = 4096;
    Xdp->RxRingSize = 128;
    Xdp->TxBufferCount = 4096;
    Xdp->TxRingSize = 128;
    Xdp->TxAlwaysPoke = FALSE;

    FILE *File = fopen("xdp.ini", "r");
    if (File == NULL) {
        return;
    }

    char Line[256];
    while (fgets(Line, sizeof(Line), File) != NULL) {
        char* Value = strchr(Line, '=');
        if (Value == NULL) {
            continue;
        }
        *Value++ = '\0';
        if (Value[strlen(Value) - 1] == '\n') {
            Value[strlen(Value) - 1] = '\0';
        }

        if (strcmp(Line, "IfIndex") == 0) {
            Xdp->IfIndex = (uint16_t)strtoul(Value, NULL, 10);
            (void)CxPlatGetInterfaceRssQueueCount(Xdp->IfIndex, &Xdp->QueueCount);
        } else if (strcmp(Line, "CpuGroup") == 0) {
             Xdp->DatapathCpuGroup = (uint16_t)strtoul(Value, NULL, 10);
             Xdp->Affinitize = TRUE;
        } else if (strcmp(Line, "CpuNumber") == 0) {
             Xdp->DatapathCpuNumber = (uint8_t)strtoul(Value, NULL, 10);
             Xdp->Affinitize = TRUE;
        } else if (strcmp(Line, "RxBufferCount") == 0) {
             Xdp->RxBufferCount = strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "RxRingSize") == 0) {
             Xdp->RxRingSize = strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "TxBufferCount") == 0) {
             Xdp->TxBufferCount = strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "TxRingSize") == 0) {
             Xdp->TxRingSize = strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "TxAlwaysPoke") == 0) {
             Xdp->TxAlwaysPoke = !!strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "SkipXsum") == 0) {
            BOOLEAN State = !!strtoul(Value, NULL, 10);
            Xdp->OffloadStatus.Transmit.NetworkLayerXsum = State;
            Xdp->OffloadStatus.Transmit.TransportLayerXsum = State;
            Xdp->OffloadStatus.Receive.NetworkLayerXsum = State;
            Xdp->OffloadStatus.Receive.TransportLayerXsum = State;
            printf("SkipXsum: %u\n", State);
        } else if (strcmp(Line, "ExtraThreads") == 0) {
            Xdp->ExtraThreads = strtoul(Value, NULL, 10);
        }
    }

    fclose(File);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
size_t
CxPlatDpRawGetDapathSize(
    void
    )
{
    return sizeof(XDP_DATAPATH);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInitialize(
    _Inout_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t ClientRecvContextLength
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;
    CXPLAT_THREAD_CONFIG Config = {
        0, 0, "XdpDatapathWorker", CxPlatXdpWorkerThread, Xdp
    };
    const uint32_t RxHeadroom = sizeof(XDP_RX_PACKET) + ALIGN_UP(ClientRecvContextLength, uint32_t);
    const uint32_t RxPacketSize = ALIGN_UP(RxHeadroom + MAX_ETH_FRAME_SIZE, XDP_RX_PACKET);
    QUIC_STATUS Status;

    CxPlatXdpReadConfig(Xdp);
    Datapath->Cpu = Xdp->DatapathCpuNumber;
    CxPlatDpRawGenerateCpuTable(Datapath);

    Xdp->Queues = CxPlatAlloc(Xdp->QueueCount * sizeof(*Xdp->Queues), QUEUE_TAG);
    if (Xdp->Queues == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "XDP Queues",
            Xdp->QueueCount * sizeof(*Xdp->Queues));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    CxPlatZeroMemory(Xdp->Queues, Xdp->QueueCount * sizeof(*Xdp->Queues));

    for (uint32_t QueueIndex = 0; QueueIndex < Xdp->QueueCount; QueueIndex++) {
        XDP_QUEUE* Queue = &Xdp->Queues[QueueIndex];

        InitializeSListHead(&Queue->RxPool);
        InitializeSListHead(&Queue->TxPool);
        CxPlatLockInitialize(&Queue->TxLock);
        CxPlatListInitializeHead(&Queue->TxQueue);
        CxPlatListInitializeHead(&Queue->WorkerTxQueue);

        //
        // RX datapath.
        //

        Queue->RxBuffers = CxPlatAlloc(Xdp->RxBufferCount * RxPacketSize, RX_BUFFER_TAG);
        if (Queue->RxBuffers == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "XDP RX Buffers",
                Xdp->RxBufferCount * RxPacketSize);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }

        Status = XskCreate(&Queue->RxXsk);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskCreate");
            goto Error;
        }

        XSK_UMEM_REG RxUmem = {0};
        RxUmem.address = Queue->RxBuffers;
        RxUmem.chunkSize = RxPacketSize;
        RxUmem.headroom = RxHeadroom;
        RxUmem.totalSize = Xdp->RxBufferCount * RxPacketSize;

        Status = XskSetSockopt(Queue->RxXsk, XSK_SOCKOPT_UMEM_REG, &RxUmem, sizeof(RxUmem));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_UMEM_REG)");
            goto Error;
        }

        Status =
            XskSetSockopt(
                Queue->RxXsk, XSK_SOCKOPT_RX_FILL_RING_SIZE, &Xdp->RxRingSize,
                sizeof(Xdp->RxRingSize));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_RX_FILL_RING_SIZE)");
            goto Error;
        }

        Status =
            XskSetSockopt(
                Queue->RxXsk, XSK_SOCKOPT_RX_RING_SIZE, &Xdp->RxRingSize, sizeof(Xdp->RxRingSize));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_RX_RING_SIZE)");
            goto Error;
        }

        uint32_t QueueId = QueueIndex;
        uint32_t Flags = 0;     // TODO: support native/generic forced flags.
        Status = XskBind(Queue->RxXsk, Xdp->IfIndex, QueueId, Flags, NULL);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskBind");
            goto Error;
        }

        XSK_RING_INFO_SET RxRingInfo;
        uint32_t RxRingInfoSize = sizeof(RxRingInfo);
        Status = XskGetSockopt(Queue->RxXsk, XSK_SOCKOPT_RING_INFO, &RxRingInfo, &RxRingInfoSize);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskGetSockopt(XSK_SOCKOPT_RING_INFO)");
            goto Error;
        }

        XskRingInitialize(&Queue->RxFillRing, &RxRingInfo.fill);
        XskRingInitialize(&Queue->RxRing, &RxRingInfo.rx);

        XDP_RULE RxRule = {
            .Match = XDP_MATCH_UDP,
            .Action = XDP_PROGRAM_ACTION_REDIRECT,
            .Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK,
            .Redirect.Target = Queue->RxXsk,
        };

        static const XDP_HOOK_ID RxHook = {
            .Layer = XDP_HOOK_L2,
            .Direction = XDP_HOOK_RX,
            .SubLayer = XDP_HOOK_INSPECT,
        };

        Flags = 0; // TODO: support native/generic forced flags.
        Status =
            XdpCreateProgram(Xdp->IfIndex, &RxHook, QueueId, Flags, &RxRule, 1, &Queue->RxProgram);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XdpCreateProgram");
            goto Error;
        }

        for (uint32_t i = 0; i < Xdp->RxBufferCount; i++) {
            InterlockedPushEntrySList(
                &Queue->RxPool, (PSLIST_ENTRY)&Queue->RxBuffers[i * RxPacketSize]);
        }

        //
        // TX datapath.
        //

        Queue->TxBuffers = CxPlatAlloc(Xdp->TxBufferCount * sizeof(XDP_TX_PACKET), TX_BUFFER_TAG);
        if (Queue->TxBuffers == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "XDP TX Buffers",
                Xdp->TxBufferCount * sizeof(XDP_TX_PACKET));
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }

        Status = XskCreate(&Queue->TxXsk);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskCreate");
            goto Error;
        }

        XSK_UMEM_REG TxUmem = {0};
        TxUmem.address = Queue->TxBuffers;
        TxUmem.chunkSize = sizeof(XDP_TX_PACKET);
        TxUmem.headroom = FIELD_OFFSET(XDP_TX_PACKET, FrameBuffer);
        TxUmem.totalSize = Xdp->TxBufferCount * sizeof(XDP_TX_PACKET);

        Status = XskSetSockopt(Queue->TxXsk, XSK_SOCKOPT_UMEM_REG, &TxUmem, sizeof(TxUmem));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_UMEM_REG)");
            goto Error;
        }

        Status =
            XskSetSockopt(
                Queue->TxXsk, XSK_SOCKOPT_TX_RING_SIZE, &Xdp->TxRingSize, sizeof(Xdp->TxRingSize));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_TX_RING_SIZE)");
            goto Error;
        }

        Status =
            XskSetSockopt(
                Queue->TxXsk, XSK_SOCKOPT_TX_COMPLETION_RING_SIZE, &Xdp->TxRingSize,
                sizeof(Xdp->TxRingSize));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_TX_COMPLETION_RING_SIZE)");
            goto Error;
        }

        Flags = 0; // TODO: support native/generic forced flags.
        Status = XskBind(Queue->TxXsk, Xdp->IfIndex, QueueId, Flags, NULL);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskBind");
            goto Error;
        }

        XSK_RING_INFO_SET TxRingInfo;
        uint32_t TxRingInfoSize = sizeof(TxRingInfo);
        Status = XskGetSockopt(Queue->TxXsk, XSK_SOCKOPT_RING_INFO, &TxRingInfo, &TxRingInfoSize);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskGetSockopt(XSK_SOCKOPT_RING_INFO)");
            goto Error;
        }

        XskRingInitialize(&Queue->TxRing, &TxRingInfo.tx);
        XskRingInitialize(&Queue->TxCompletionRing, &TxRingInfo.completion);

        for (uint32_t i = 0; i < Xdp->TxBufferCount; i++) {
            InterlockedPushEntrySList(
                &Queue->TxPool, (PSLIST_ENTRY)&Queue->TxBuffers[i * sizeof(XDP_TX_PACKET)]);
        }
    }

    Xdp->Running = TRUE;
    Status = CxPlatThreadCreate(&Config, &Xdp->WorkerThread);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatThreadCreate");
        goto Error;
    }

    Config.Callback = CxPlatXdpExtraWorkerThread;
    for (uint32_t i = 0; i < Xdp->ExtraThreads; ++i) {
        Status = CxPlatThreadCreate(&Config, &Xdp->ExtraWorkerThreads[i]);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "CxPlatThreadCreate");
            goto Error;
        }
    }

Error:

    if (QUIC_FAILED(Status)) {
        CxPlatDpRawUninitialize(Datapath);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;

    if (Xdp->WorkerThread != NULL) {
        Xdp->Running = FALSE;
        CxPlatThreadWait(&Xdp->WorkerThread);
        CxPlatThreadDelete(&Xdp->WorkerThread);
    }

    #pragma warning(push)
    #pragma warning(disable:6001) // Using uninitialized memory

    for (uint32_t i = 0; Xdp->Queues != NULL && i < Xdp->QueueCount; i++) {
        XDP_QUEUE *Queue = &Xdp->Queues[i];

        if (Queue->TxXsk != NULL) {
            QUIC_STATUS Status;
            XSK_STATISTICS Stats;
            uint32_t StatsSize = sizeof(Stats);
            Status = XskGetSockopt(Queue->TxXsk, XSK_SOCKOPT_STATISTICS, &Stats, &StatsSize);
            if (QUIC_SUCCEEDED(Status)) {
                printf("[%u]txInvalidDescriptors: %llu\n", i, Stats.txInvalidDescriptors);
            }
            CloseHandle(Queue->TxXsk);
        }

        if (Queue->TxBuffers != NULL) {
            CxPlatFree(Queue->TxBuffers, TX_BUFFER_TAG);
        }

        if (Queue->RxProgram != NULL) {
            CloseHandle(Queue->RxProgram);
        }

        if (Queue->RxXsk != NULL) {
            QUIC_STATUS Status;
            XSK_STATISTICS Stats;
            uint32_t StatsSize = sizeof(Stats);
            Status = XskGetSockopt(Queue->RxXsk, XSK_SOCKOPT_STATISTICS, &Stats, &StatsSize);
            if (QUIC_SUCCEEDED(Status)) {
                printf("[%u]rxDropped: %llu\n", i, Stats.rxDropped);
                printf("[%u]rxInvalidDescriptors: %llu\n", i, Stats.rxInvalidDescriptors);
            }
            CloseHandle(Queue->RxXsk);
        }

        if (Queue->RxBuffers != NULL) {
            CxPlatFree(Queue->RxBuffers, RX_BUFFER_TAG);
        }

        CxPlatLockUninitialize(&Queue->TxLock);
    }

    #pragma warning(pop)

    if (Xdp->Queues != NULL) {
        CxPlatFree(Xdp->Queues, QUEUE_TAG);
    }
}

static
void
CxPlatXdpRx(
    _In_ XDP_DATAPATH* Xdp,
    _In_ XDP_QUEUE *Queue
    )
{
    CXPLAT_RECV_DATA* Buffers[RX_BATCH_SIZE];
    uint32_t RxIndex;
    uint32_t FillIndex;
    uint32_t ProdCount = 0;
    uint32_t PacketCount = 0;
    const uint32_t BuffersCount = XskRingConsumerReserve(&Queue->RxRing, RX_BATCH_SIZE, &RxIndex);

    for (uint32_t i = 0; i < BuffersCount; i++) {
        XSK_BUFFER_DESCRIPTOR* Buffer = XskRingGetElement(&Queue->RxRing, RxIndex++);
        XDP_RX_PACKET* Packet =
            (XDP_RX_PACKET*)(Queue->RxBuffers + XskDescriptorGetAddress(Buffer->address));
        uint8_t* FrameBuffer = (uint8_t*)Packet + XskDescriptorGetOffset(Buffer->address);

        CxPlatZeroMemory(Packet, sizeof(XDP_RX_PACKET));
        Packet->Route = &Packet->RouteStorage;

        CxPlatDpRawParseEthernet(
            (CXPLAT_DATAPATH*)Xdp,
            (CXPLAT_RECV_DATA*)Packet,
            FrameBuffer,
            (uint16_t)Buffer->length);

        if (Packet->Buffer) {
            Packet->Allocated = TRUE;
            Packet->Queue = Queue;
            Buffers[PacketCount++] = (CXPLAT_RECV_DATA*)Packet;
        } else {
            CxPlatListPushEntry(&Queue->WorkerRxPool, (CXPLAT_SLIST_ENTRY*)Packet);
        }
    }

    if (BuffersCount > 0) {
        XskRingConsumerRelease(&Queue->RxRing, BuffersCount);
    }

    uint32_t FillAvailable = XskRingProducerReserve(&Queue->RxFillRing, MAXUINT32, &FillIndex);
    while (FillAvailable-- > 0) {
        if (Queue->WorkerRxPool.Next == NULL) {
            Queue->WorkerRxPool.Next = (CXPLAT_SLIST_ENTRY*)InterlockedFlushSList(&Queue->RxPool);
        }

        XDP_RX_PACKET* Packet = (XDP_RX_PACKET*)CxPlatListPopEntry(&Queue->WorkerRxPool);
        if (Packet == NULL) {
            break;
        }

        uint64_t* FillDesc = XskRingGetElement(&Queue->RxFillRing, FillIndex++);
        *FillDesc = (uint8_t*)Packet - Queue->RxBuffers;
        ProdCount++;
    }

    if (ProdCount > 0) {
        XskRingProducerSubmit(&Queue->RxFillRing, ProdCount);
    }

    if (PacketCount > 0) {
        CxPlatDpRawRxEthernet((CXPLAT_DATAPATH*)Xdp, Buffers, (uint16_t)PacketCount);
    }

    if (XskRingError(&Queue->RxRing) && !Queue->Error) {
        XSK_ERROR ErrorStatus;
        QUIC_STATUS XskStatus;
        uint32_t ErrorSize = sizeof(ErrorStatus);
        XskStatus = XskGetSockopt(Queue->RxXsk, XSK_SOCKOPT_RX_ERROR, &ErrorStatus, &ErrorSize);
        printf("RX ring error: 0x%x\n", SUCCEEDED(XskStatus) ? ErrorStatus : XskStatus);
        Queue->Error = TRUE;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxFree(
    _In_opt_ const CXPLAT_RECV_DATA* PacketChain
    )
{
    uint32_t Count = 0;
    SLIST_ENTRY* Head = NULL;
    SLIST_ENTRY** Tail = &Head;
    SLIST_HEADER* Pool = NULL;

    while (PacketChain) {
        const XDP_RX_PACKET* Packet = (XDP_RX_PACKET*)PacketChain;
        PacketChain = PacketChain->Next;
        // Packet->Allocated = FALSE; (other data paths don't clear this flag?)

        if (Pool != &Packet->Queue->RxPool) {
            if (Count > 0) {
                InterlockedPushListSList(
                    Pool, Head, CONTAINING_RECORD(Tail, SLIST_ENTRY, Next), Count);
                Head = NULL;
                Tail = &Head;
                Count = 0;
            }

            Pool = &Packet->Queue->RxPool;
        }

        *Tail = (SLIST_ENTRY*)Packet;
        Tail = &((SLIST_ENTRY*)Packet)->Next;
        Count++;
    }

    if (Count > 0) {
        InterlockedPushListSList(Pool, Head, CONTAINING_RECORD(Tail, SLIST_ENTRY, Next), Count);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_SEND_DATA*
CxPlatDpRawTxAlloc(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_ECN_TYPE ECN, // unused currently
    _In_ uint16_t MaxPacketSize,
    _In_ QUIC_ADDRESS_FAMILY Family
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;

    //
    // TODO: TX spreading.
    //
    XDP_QUEUE* Queue = &Xdp->Queues[0];
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)InterlockedPopEntrySList(&Queue->TxPool);

    UNREFERENCED_PARAMETER(ECN);

    if (Packet) {
        HEADER_BACKFILL HeaderBackfill = CxPlatDpRawCalculateHeaderBackFill(Family);
        CXPLAT_DBG_ASSERT(MaxPacketSize <= sizeof(Packet->FrameBuffer) - HeaderBackfill.AllLayer);
        Packet->Queue = Queue;
        Packet->Buffer.Length = MaxPacketSize;
        Packet->Buffer.Buffer = &Packet->FrameBuffer[HeaderBackfill.AllLayer];
    }

    return (CXPLAT_SEND_DATA*)Packet;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)SendData;
    InterlockedPushEntrySList(&Packet->Queue->TxPool, (PSLIST_ENTRY)Packet);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxEnqueue(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)SendData;

    CxPlatLockAcquire(&Packet->Queue->TxLock);
    CxPlatListInsertTail(&Packet->Queue->TxQueue, &Packet->Link);
    CxPlatLockRelease(&Packet->Queue->TxLock);
}

static
void
CxPlatXdpTx(
    _In_ XDP_DATAPATH* Xdp,
    _In_ XDP_QUEUE* Queue
    )
{
    uint32_t ProdCount = 0;
    uint32_t CompCount = 0;
    SLIST_ENTRY* TxCompleteHead = NULL;
    SLIST_ENTRY** TxCompleteTail = &TxCompleteHead;

    if (CxPlatListIsEmpty(&Queue->WorkerTxQueue) &&
        ReadPointerNoFence(&Queue->TxQueue.Flink) != &Queue->TxQueue) {
        CxPlatLockAcquire(&Queue->TxLock);
        CxPlatListMoveItems(&Queue->TxQueue, &Queue->WorkerTxQueue);
        CxPlatLockRelease(&Queue->TxLock);
    }

    uint32_t TxIndex;
    uint32_t TxAvailable = XskRingProducerReserve(&Queue->TxRing, MAXUINT32, &TxIndex);
    while (TxAvailable-- > 0 && !CxPlatListIsEmpty(&Queue->WorkerTxQueue)) {
        XSK_BUFFER_DESCRIPTOR* Buffer = XskRingGetElement(&Queue->TxRing, TxIndex++);
        CXPLAT_LIST_ENTRY* Entry = CxPlatListRemoveHead(&Queue->WorkerTxQueue);
        XDP_TX_PACKET* Packet = CONTAINING_RECORD(Entry, XDP_TX_PACKET, Link);

        Buffer->address = (uint8_t*)Packet - Queue->TxBuffers;
        XskDescriptorSetOffset(&Buffer->address, FIELD_OFFSET(XDP_TX_PACKET, FrameBuffer));
        Buffer->length = Packet->Buffer.Length;
        ProdCount++;
    }

    if (ProdCount > 0) {
        XskRingProducerSubmit(&Queue->TxRing, ProdCount);
        if (Xdp->TxAlwaysPoke || XskRingProducerNeedPoke(&Queue->TxRing)) {
            uint32_t OutFlags;
            QUIC_STATUS Status = XskNotifySocket(Queue->TxXsk, XSK_NOTIFY_POKE_TX, 0, &OutFlags);
            CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
            UNREFERENCED_PARAMETER(Status);
        }
    }

    uint32_t CompIndex;
    uint32_t CompAvailable =
        XskRingConsumerReserve(&Queue->TxCompletionRing, MAXUINT32, &CompIndex);
    while (CompAvailable-- > 0) {
        uint64_t* CompDesc = XskRingGetElement(&Queue->TxCompletionRing, CompIndex++);
        XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)(Queue->TxBuffers + *CompDesc);
        *TxCompleteTail = (PSLIST_ENTRY)Packet;
        TxCompleteTail = &((PSLIST_ENTRY)Packet)->Next;
        CompCount++;
    }

    if (CompCount > 0) {
        XskRingConsumerRelease(&Queue->TxCompletionRing, CompCount);
        InterlockedPushListSList(
            &Queue->TxPool, TxCompleteHead, CONTAINING_RECORD(TxCompleteTail, SLIST_ENTRY, Next),
            CompCount);
    }

    if (XskRingError(&Queue->TxRing) && !Queue->Error) {
        XSK_ERROR ErrorStatus;
        QUIC_STATUS XskStatus;
        uint32_t ErrorSize = sizeof(ErrorStatus);
        XskStatus = XskGetSockopt(Queue->TxXsk, XSK_SOCKOPT_TX_ERROR, &ErrorStatus, &ErrorSize);
        printf("TX ring error: 0x%x\n", SUCCEEDED(XskStatus) ? ErrorStatus : XskStatus);
        Queue->Error = TRUE;
    }
}

CXPLAT_THREAD_CALLBACK(CxPlatXdpWorkerThread, Context)
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Context;

#ifdef QUIC_USE_EXECUTION_CONTEXTS
    const CXPLAT_THREAD_ID ThreadID = CxPlatCurThreadID();
#endif

    if (Xdp->Affinitize) {
        GROUP_AFFINITY Affinity = {0};

        Affinity.Group = Xdp->DatapathCpuGroup;
        Affinity.Mask = (ULONG_PTR)1 << Xdp->DatapathCpuNumber;
        SetThreadGroupAffinity(GetCurrentThread(), &Affinity, NULL);
    }

    while (Xdp->Running) {
        for (uint32_t i = 0; i < Xdp->QueueCount; i++) {
            XDP_QUEUE* Queue = &Xdp->Queues[i];

            CxPlatXdpRx(Xdp, Queue);
            CxPlatXdpTx(Xdp, Queue);

#ifdef QUIC_USE_EXECUTION_CONTEXTS
        (void)CxPlatRunExecutionContexts(ThreadID);
#endif
        }
    }

    return 0;
}

CXPLAT_THREAD_CALLBACK(CxPlatXdpExtraWorkerThread, Context)
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Context;

    if (Xdp->Affinitize) {
        GROUP_AFFINITY Affinity = {0};

        Affinity.Group = Xdp->DatapathCpuGroup;
        Affinity.Mask = (ULONG_PTR)1 << Xdp->DatapathCpuNumber;
        SetThreadGroupAffinity(GetCurrentThread(), &Affinity, NULL);
    }

    while (Xdp->Running) {
        CxPlatTimeUs64();
    }

    return 0;
}
