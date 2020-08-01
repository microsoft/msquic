/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include <Natupnp.h>
#include <UPnP.h>
#include <comutil.h>
#include "QuicUPnP.h"

#include <stdio.h>

typedef struct QUIC_UPNP {

    IUPnPNAT* NAT;
    IStaticPortMappingCollection* PortCollection;

} QUIC_UPNP;

extern "C"
QUIC_UPNP*
QuicUPnPInitialize(
    void
    )
{
    HRESULT hr;
    if (FAILED(hr = CoInitialize(NULL))) {
        printf("CoInitialize failed, 0x%x\n", hr);
        return nullptr;
    }

    QUIC_UPNP* UPnP = new QUIC_UPNP;
    ZeroMemory(UPnP, sizeof(UPnP));

    hr = CoCreateInstance(__uuidof(UPnPNAT), NULL, CLSCTX_ALL, __uuidof(IUPnPNAT), (void **)&UPnP->NAT);
    if (FAILED(hr)) {
        printf("CoCreateInstance(UPnPNAT) failed, 0x%x\n", hr);
        QuicUPnPUninitialize(UPnP);
        return nullptr;
    }

    hr = UPnP->NAT->get_StaticPortMappingCollection(&UPnP->PortCollection);
    if (FAILED(hr) || !UPnP->PortCollection) {
        printf("get_StaticPortMappingCollection failed, 0x%x\n", hr);
        QuicUPnPUninitialize(UPnP);
        return nullptr;
    }

    return UPnP;
}

extern "C"
void
QuicUPnPUninitialize(
    QUIC_UPNP* UPnP
    )
{
    if (UPnP) {
        if (UPnP->PortCollection) {
            UPnP->PortCollection->Release();
        }
        if (UPnP->NAT) {
            UPnP->NAT->Release();
        }
        delete UPnP;
        CoUninitialize();
    }
}

extern "C"
void
QuicUPnPDumpStaticMappings(
    QUIC_UPNP* UPnP
    )
{
    HRESULT hr;
    IEnumVARIANT* Enumerator;
    hr = UPnP->PortCollection->get__NewEnum((IUnknown**)&Enumerator);
    if (FAILED(hr)) {
        printf("get__NewEnum failed, 0x%x\n", hr);
        return;
    }

    hr = Enumerator->Reset();
    if (FAILED(hr)) {
        printf("Reset failed, 0x%x\n", hr);
        Enumerator->Release();
        return;
    }

    printf("UPnP Static Mappings:\n");

    do {
        VARIANT varCurMapping;
        VariantInit(&varCurMapping);

        IStaticPortMapping* piMapping = NULL;
        BSTR ExtIPAddr = NULL;
        long ExtPort = 0;
        long IntPort = 0;
        BSTR Protocol = NULL;
        BSTR IntClient = NULL;
        VARIANT_BOOL Enabled = VARIANT_FALSE;
        BSTR Description = NULL;

        hr = Enumerator->Next(1, &varCurMapping, NULL);
        if (FAILED(hr) || varCurMapping.vt == VT_EMPTY) {
            break;
        }

        IDispatch* piDispMap = V_DISPATCH(&varCurMapping);
        hr = piDispMap->QueryInterface(IID_IStaticPortMapping, (void**)&piMapping);
        if (FAILED(hr)) {
            printf("QueryInterface(IStaticPortMapping) failed, 0x%x\n", hr);
            goto Done;
        }

        hr = piMapping->get_ExternalIPAddress(&ExtIPAddr);
        if (FAILED(hr)) {
            printf("get_ExternalIPAddress failed, 0x%x\n", hr);
            goto Done;
        }

        hr = piMapping->get_ExternalPort(&ExtPort);
        if (FAILED(hr)) {
            printf("get_ExternalPort failed, 0x%x\n", hr);
            goto Done;
        }

        hr = piMapping->get_InternalPort(&IntPort);
        if (FAILED(hr)) {
            printf("get_InternalPort failed, 0x%x\n", hr);
            goto Done;
        }

        hr = piMapping->get_Protocol(&Protocol);
        if (FAILED(hr)) {
            printf("get_Protocol failed, 0x%x\n", hr);
            goto Done;
        }

        hr = piMapping->get_InternalClient(&IntClient);
        if (FAILED(hr)) {
            printf("get_InternalClient failed, 0x%x\n", hr);
            goto Done;
        }

        hr = piMapping->get_Enabled(&Enabled);
        if (FAILED(hr)) {
            printf("get_Enabled failed, 0x%x\n", hr);
            goto Done;
        }

        hr = piMapping->get_Description(&Description);
        if (FAILED(hr)) {
            printf("get_Description failed, 0x%x\n", hr);
            goto Done;
        }

        printf("[%s] [%ws] %ws:%u -> %ws:%u [%ws]\n",
            (Enabled == VARIANT_FALSE ? "disabled" : "enabled"),
            Protocol, ExtIPAddr, ExtPort, IntClient, IntPort, Description);

    Done:

        SysFreeString(Protocol);
        SysFreeString(ExtIPAddr);
        SysFreeString(IntClient);
        SysFreeString(Description);

        if (piMapping) {
            piMapping->Release();
        }
	    VariantClear(&varCurMapping);

    } while (!FAILED(hr));

    Enumerator->Release();
}

extern "C"
int
QuicUPnPAddStaticMapping(
    QUIC_UPNP* UPnP,
    const char* Protocol,
    const char* ExternalIP,
    uint16_t ExternalPort,
    const char* InternalIP,
    uint16_t InternalPort,
    const char* Description
    )
{
    BSTR bstrProtocol = _com_util::ConvertStringToBSTR(Protocol);
    BSTR bstrExternalIP = _com_util::ConvertStringToBSTR(ExternalIP);
    BSTR bstrInternalIP = _com_util::ConvertStringToBSTR(InternalIP);
    BSTR bstrDescription = _com_util::ConvertStringToBSTR(Description);

    printf("Adding [%ws] %ws:%u -> %ws:%u [%ws]\n",
        bstrProtocol, bstrExternalIP, ExternalPort, bstrInternalIP, InternalPort, bstrDescription);

    IStaticPortMapping* Mapping = nullptr;
    HRESULT hr =
        UPnP->PortCollection->Add(
            ExternalPort,
            bstrProtocol,
            InternalPort,
            bstrInternalIP,
            VARIANT_TRUE,
            bstrDescription,
            &Mapping);
    if (FAILED(hr)) {
        printf("Add failed, 0x%x\n", hr);
    }
    if (Mapping) {
        Mapping->Release();
    }

    SysFreeString(bstrProtocol);
    SysFreeString(bstrExternalIP);
    SysFreeString(bstrInternalIP);
    SysFreeString(bstrDescription);

    return FAILED(hr) ? 1 : 0;
}

extern "C"
int
QuicUPnPRemoveStaticMapping(
    QUIC_UPNP* UPnP,
    const char* Protocol,
    uint16_t ExternalPort
    )
{
    BSTR bstrProtocol = _com_util::ConvertStringToBSTR(Protocol);

    printf("Removing [%ws] :%u\n", bstrProtocol, ExternalPort);

    HRESULT hr =
        UPnP->PortCollection->Remove(
            ExternalPort,
            bstrProtocol);
    if (FAILED(hr)) {
        printf("Remove failed, 0x%x\n", hr);
    }

    SysFreeString(bstrProtocol);

    return FAILED(hr) ? 1 : 0;
}
