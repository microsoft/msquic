/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "msquichelper.h"
#include "quic_pcp.h"

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_PCP_CALLBACK)
void
PcpCallback(
    _In_ CXPLAT_PCP* /* PcpContext */,
    _In_ void* /* Context */,
    _In_ const CXPLAT_PCP_EVENT* Event
    )
{
    switch (Event->Type) {
    case CXPLAT_PCP_EVENT_FAILURE:
        printf("Received failure result, %hhu\n", Event->FAILURE.ErrorCode);
        break;
    case CXPLAT_PCP_EVENT_MAP: {
        QUIC_ADDR_STR ExternalAddr;
        QuicAddrToString(Event->MAP.ExternalAddress, &ExternalAddr);
        printf("Response: %s maps to :%hu for %u seconds\n",
            ExternalAddr.Address,
            QuicAddrGetPort(Event->MAP.InternalAddress),
            Event->MAP.LifetimeSeconds);
        break;
    }
    case CXPLAT_PCP_EVENT_PEER: {
        QUIC_ADDR_STR ExternalAddrStr, RemotePeerAddrStr;
        QuicAddrToString(Event->PEER.ExternalAddress, &ExternalAddrStr);
        QuicAddrToString(Event->PEER.RemotePeerAddress, &RemotePeerAddrStr);
        printf("Response: %s (to peer %s) maps to :%hu for %u seconds\n",
            ExternalAddrStr.Address,
            RemotePeerAddrStr.Address,
            QuicAddrGetPort(Event->PEER.InternalAddress),
            Event->PEER.LifetimeSeconds);
        break;
    }
    }
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    uint8_t PcpNonce[12];
    CXPLAT_DATAPATH* Datapath = nullptr;
    CXPLAT_PCP* PcpContext = nullptr;
    int ErrorCode = -1;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    CxPlatSystemLoad();
    CxPlatInitialize();
    CxPlatRandom(sizeof(PcpNonce), PcpNonce);
    CxPlatDataPathInitialize(0, nullptr, nullptr, nullptr, &Datapath);

    QUIC_STATUS Status =
        CxPlatPcpInitialize(
            Datapath,
            PcpNonce,
            PcpCallback,
            &PcpContext);
    if (QUIC_FAILED(Status)) {
        printf("CxPlatPcpInitialize failed, 0x%x\n", Status);
        goto Error;
    }

    printf("Sending MAP request...\n");
    Status = CxPlatPcpSendMapRequest(PcpContext, PcpNonce, nullptr, 1234, 360000);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }
    CxPlatSleep(1000);

    printf("Sending (delete) MAP request...\n");
    Status = CxPlatPcpSendMapRequest(PcpContext, PcpNonce, nullptr, 1234, 0);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }
    CxPlatSleep(1000);

    ErrorCode = 1;

Error:

    if (PcpContext) {
        CxPlatPcpUninitialize(PcpContext);
    }
    CxPlatDataPathUninitialize(Datapath);
    CxPlatUninitialize();
    CxPlatSystemUnload();

    return ErrorCode;
}
