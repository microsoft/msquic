/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC XDP Datapath Implementation (User Mode)

--*/

#define _CRT_SECURE_NO_WARNINGS 1 // TODO - Remove

#include "datapath_raw_win.h"
#include "datapath_raw_xdp.h"
#include <wbemidl.h>
#include <afxdp_helper.h>
#include <xdpapi.h>
#include <xdpapi_experimental.h>
#include <stdio.h>

#ifdef QUIC_CLOG
#include "datapath_raw_xdp_winuser.c.clog.h"
#endif

QUIC_STATUS
CxPlatGetInterfaceRssQueueCount(
    _In_ XDP_DATAPATH* Xdp,
    _In_ HANDLE XdpHandle,
    _In_ uint32_t InterfaceIndex,
    _Out_ uint16_t* Count
    )
{
    HRESULT hRes;
    IWbemLocator *pLoc = NULL;
    IEnumWbemClassObject *pEnum = NULL;
    IWbemServices *pSvc = NULL;
    DWORD ret = 0;
    uint16_t cnt = 0;
    NET_LUID if_luid = { 0 };
    WCHAR if_alias[256 + 1] = { 0 };

    UNREFERENCED_PARAMETER(Xdp);
    UNREFERENCED_PARAMETER(XdpHandle);

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

    // Step 2: ---------------------------------------------------
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

    // Step 3: -----------------------------------------------------
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

    // Step 4: --------------------------------------------------
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

    // Step 5: --------------------------------------------------
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

    // Step 6: -------------------------------------------------
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
            CXPLAT_FRE_ASSERT(cnt != 0);
        } else if ((vtProp.vt & VT_ARRAY) == 0) {
            //AF_XDP_LOG(ERR, "not ARRAY\n");
        } else {
            long lLower, lUpper;
            SAFEARRAY *pSafeArray = vtProp.parray;
            UINT8 *rssTable = NULL;
            DWORD rssTableSize;
            DWORD numberOfProcs;
            DWORD numberOfProcGroups;

            SafeArrayGetLBound(pSafeArray, 1, &lLower);
            SafeArrayGetUBound(pSafeArray, 1, &lUpper);

            IUnknown** rawArray;
            SafeArrayAccessData(pSafeArray, (void**)&rawArray);

            // Set up the RSS table according to number of procs and proc groups.
            numberOfProcs = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
            numberOfProcGroups = GetActiveProcessorGroupCount();
            rssTableSize = numberOfProcs * numberOfProcGroups;
            rssTable = malloc(rssTableSize);
            memset(rssTable, 0, rssTableSize);

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
                    free(rssTable);
                    hRes = QUIC_STATUS_OUT_OF_MEMORY;
                    goto Cleanup;
                }

                hr = obj->lpVtbl->Get(obj, L"ProcessorNumber", 0, &vtProp, 0, 0);
                UINT32 procNum = vtProp.iVal;
                VariantClear(&vtProp);
                hr = obj->lpVtbl->Get(obj, L"ProcessorGroup", 0, &vtProp, 0, 0);
                UINT32 groupNum = vtProp.iVal;
                VariantClear(&vtProp);
                CXPLAT_DBG_ASSERT(groupNum < numberOfProcGroups);
                CXPLAT_DBG_ASSERT(procNum < numberOfProcs);
                *(rssTable + groupNum * numberOfProcs + procNum) = 1;
                obj->lpVtbl->Release(obj);
            }

            SafeArrayUnaccessData(pSafeArray);

            // Count unique RSS procs by counting ones in rssTable.
            for (DWORD i = 0; i < rssTableSize; ++i) {
                cnt += rssTable[i];
            }

            free(rssTable);
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
    //
    // Default config.
    //
    Xdp->RxBufferCount = 8192;
    Xdp->RxRingSize = 256;
    Xdp->TxBufferCount = 8192;
    Xdp->TxRingSize = 256;
    Xdp->TxAlwaysPoke = FALSE;

    //
    // Read config from config file.
    //
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

        if (strcmp(Line, "RxBufferCount") == 0) {
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
            Xdp->SkipXsum = State;
            printf("SkipXsum: %u\n", State);
        }
    }

    fclose(File);
}

QUIC_STATUS
CxPlatXdpInitialize(
    _In_ XDP_DATAPATH* Xdp
    )
{
    if (QUIC_FAILED(XdpLoadApi(XDP_API_VERSION_1, &Xdp->XdpApiLoadContext, &Xdp->XdpApi))) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    Xdp->XdpQeoSet = (XDP_QEO_SET_FN *)Xdp->XdpApi->XdpGetRoutine(XDP_QEO_SET_FN_NAME);

    return QUIC_STATUS_SUCCESS;
}

VOID
CxPlatXdpUninitialize(
    _In_ XDP_DATAPATH* Xdp
    )
{
    if (Xdp->XdpApi) {
        XdpUnloadApi(Xdp->XdpApiLoadContext, Xdp->XdpApi);
    }
}

QUIC_STATUS
CxPlatXdpDiscoverInterfaces(
    _In_ XDP_DATAPATH* Xdp,
    _In_ uint32_t ClientRecvContextLength,
    _In_ CXPLAT_XDP_CREATE_INTERFACE_FN CreateInterface
    )
{
    QUIC_STATUS Status;

    PMIB_IF_TABLE2 pIfTable = NULL;
    if (GetIfTable2(&pIfTable) != NO_ERROR) {
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

    PIP_ADAPTER_ADDRESSES Adapters = NULL;
    ULONG Error;
    ULONG AdaptersBufferSize = 15000; // 15 KB buffer for GAA to start with.
    ULONG Iterations = 0;
    ULONG flags = // skip info that we don't need.
        GAA_FLAG_INCLUDE_PREFIX |
        GAA_FLAG_SKIP_UNICAST |
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_DNS_INFO;

    do {
        Adapters = (IP_ADAPTER_ADDRESSES*)CxPlatAlloc(AdaptersBufferSize, ADAPTER_TAG);
        if (Adapters == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "XDP interface",
                AdaptersBufferSize);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }

        Error =
            GetAdaptersAddresses(AF_UNSPEC, flags, NULL, Adapters, &AdaptersBufferSize);
        if (Error == ERROR_BUFFER_OVERFLOW) {
            CxPlatFree(Adapters, ADAPTER_TAG);
            Adapters = NULL;
        } else {
            break;
        }

        Iterations++;
    } while ((Error == ERROR_BUFFER_OVERFLOW) && (Iterations < 3)); // retry up to 3 times.

    if (Error == NO_ERROR) {
        Status = QUIC_STATUS_SUCCESS;
        for (PIP_ADAPTER_ADDRESSES Adapter = Adapters; Adapter != NULL; Adapter = Adapter->Next) {
            if (Adapter->IfType == IF_TYPE_ETHERNET_CSMACD &&
                Adapter->OperStatus == IfOperStatusUp &&
                Adapter->PhysicalAddressLength == ETH_MAC_ADDR_LEN) {

                // Look for VF which associated with Adapter
                // It has same MAC address. and empirically these flags
                uint32_t ActualIfIndex = Adapter->IfIndex;
                for (int i = 0; i < (int) pIfTable->NumEntries; i++) {
                    MIB_IF_ROW2* pIfRow = &pIfTable->Table[i];
                    if (!pIfRow->InterfaceAndOperStatusFlags.FilterInterface &&
                         pIfRow->InterfaceAndOperStatusFlags.HardwareInterface &&
                         pIfRow->InterfaceAndOperStatusFlags.ConnectorPresent &&
                         pIfRow->PhysicalMediumType == NdisPhysicalMedium802_3 &&
                         memcmp(&pIfRow->PhysicalAddress, &Adapter->PhysicalAddress,
                                Adapter->PhysicalAddressLength) == 0) {
                        ActualIfIndex = pIfRow->InterfaceIndex;
                        QuicTraceLogInfo(
                            FoundVF,
                            "[ xdp][%p] Found NetSvc-VF interfaces. NetSvc IfIdx:%lu, VF IfIdx:%lu",
                            Xdp,
                            Adapter->IfIndex,
                            ActualIfIndex);
                        break; // assuming there is 1:1 matching
                    }
                }

                Status =
                    CreateInterface(
                        Xdp, Adapter->IfIndex, ActualIfIndex, Adapter->PhysicalAddress, ClientRecvContextLength);
                if (QUIC_FAILED(Status)) {
                    goto Error;
                }
            }
        }
    } else {
        Status = HRESULT_FROM_WIN32(Error);
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "GetAdaptersAddresses");
        goto Error;
    }

Error:

    if (pIfTable != NULL) {
        FreeMibTable(pIfTable);
    }

    return Status;
}

XDP_STATUS
CxPlatXdpCreateXsk(
    _In_ const XDP_DATAPATH* Xdp,
    _Out_ HANDLE* Xsk
    )
{
    return Xdp->XdpApi->XskCreate(Xsk);
}

XDP_STATUS
CxPlatXdpXskSetSockopt(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk,
    _In_ uint32_t OptionName,
    _In_ void* OptionValue,
    _In_ uint32_t OptionLength
    )
{
    return Xdp->XdpApi->XskSetSockopt(Xsk, OptionName, OptionValue, OptionLength);
}

XDP_STATUS
CxPlatXdpXskGetSockopt(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk,
    _In_ uint32_t OptionName,
    _Out_writes_bytes_(*OptionLength) void* OptionValue,
    _Inout_ uint32_t* OptionLength
    )
{
    return Xdp->XdpApi->XskGetSockopt(Xsk, OptionName, OptionValue, OptionLength);
}

XDP_STATUS
CxPlatXdpXskBind(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk,
    _In_ uint32_t IfIndex,
    _In_ uint32_t QueueId,
    _In_ XSK_BIND_FLAGS Flags
    )
{
    return Xdp->XdpApi->XskBind(Xsk, IfIndex, QueueId, Flags);
}

XDP_STATUS
CxPlatXdpXskActivate(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk,
    _In_ XSK_ACTIVATE_FLAGS Flags
    )
{
    return Xdp->XdpApi->XskActivate(Xsk, Flags);
}

XDP_STATUS
CxPlatXdpXskPokeTx(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk
    )
{
    XSK_NOTIFY_RESULT_FLAGS OutFlags;
    return Xdp->XdpApi->XskNotifySocket(Xsk, XSK_NOTIFY_FLAG_POKE_TX, 0, &OutFlags);
}

XDP_STATUS
CxPlatXdpXskNotifyAsync(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk,
    _In_ XSK_NOTIFY_FLAGS Flags,
    _Inout_ XSK_COMPLETION_CONTEXT CompletionContext,
    _Out_ XSK_NOTIFY_RESULT_FLAGS* Result
    )
{
    *Result = 0;
    return Xdp->XdpApi->XskNotifyAsync(Xsk, Flags, CompletionContext);
}

VOID
CxPlatXdpCloseXsk(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk
    )
{
    UNREFERENCED_PARAMETER(Xdp);
    CloseHandle(Xsk);
}

XDP_STATUS
CxPlatXdpCreateProgram(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ uint32_t InterfaceIndex,
    _In_ CONST XDP_HOOK_ID* HookId,
    _In_ uint32_t QueueId,
    _In_ XDP_CREATE_PROGRAM_FLAGS Flags,
    _In_reads_(RuleCount) CONST XDP_RULE* Rules,
    _In_ uint32_t RuleCount,
    _Out_ HANDLE* Program
    )
{
    return
        Xdp->XdpApi->XdpCreateProgram(
            InterfaceIndex,
            HookId,
            QueueId,
            Flags,
            Rules,
            RuleCount,
            Program);
}

VOID
CxPlatXdpCloseProgram(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Program
    )
{
    UNREFERENCED_PARAMETER(Xdp);
    CloseHandle(Program);
}

XDP_STATUS
CxPlatXdpOpenInterface(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ uint32_t IfIndex,
    _Out_ HANDLE* Interface
    )
{
    return Xdp->XdpApi->XdpInterfaceOpen(IfIndex, Interface);
}

VOID
CxPlatXdpCloseInterface(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Interface
    )
{
    UNREFERENCED_PARAMETER(Xdp);
    CloseHandle(Interface);
}
