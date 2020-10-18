/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include <msquichelper.h>
#include <quic_pcp.h>

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_DATAPATH_RECEIVE_CALLBACK)
void
UdpRecvCallback(
    _In_ QUIC_DATAPATH_BINDING* /* Binding */,
    _In_ void* /* Context */,
    _In_ QUIC_RECV_DATAGRAM* RecvBufferChain
    )
{
    QuicDataPathBindingReturnRecvDatagrams(RecvBufferChain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_DATAPATH_UNREACHABLE_CALLBACK)
void
UdpUnreachCallback(
    _In_ QUIC_DATAPATH_BINDING* /* Binding */,
    _In_ void* /* Context */,
    _In_ const QUIC_ADDR* /* RemoteAddress */
    )
{
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_PCP_CALLBACK)
void
PcpCallback(
    _In_ QUIC_PCP* /* PcpContext */,
    _In_ void* /* Context */,
    _In_ const QUIC_PCP_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_PCP_EVENT_FAILURE:
        printf("Received failure result, %hhu\n", Event->FAILURE.ErrorCode);
        break;
    case QUIC_PCP_EVENT_MAP: {
        QUIC_ADDR_STR ExternalAddr;
        QuicAddrToString(Event->MAP.ExternalAddress, &ExternalAddr);
        printf("Response: %s maps to :%hu for %u seconds\n",
            ExternalAddr.Address,
            QuicAddrGetPort(Event->MAP.InternalAddress),
            Event->MAP.LifetimeSeconds);
        break;
    }
    case QUIC_PCP_EVENT_PEER: {
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
    QUIC_DATAPATH* Datapath = nullptr;
    QUIC_PCP* PcpContext = nullptr;
    int ErrorCode = -1;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    QuicPlatformSystemLoad();
    QuicPlatformInitialize();
    QuicRandom(sizeof(PcpNonce), PcpNonce);
    QuicDataPathInitialize(
        0,
        UdpRecvCallback,
        UdpUnreachCallback,
        &Datapath);

    QUIC_STATUS Status =
        QuicPcpInitialize(
            Datapath,
            PcpNonce,
            PcpCallback,
            &PcpContext);
    if (QUIC_FAILED(Status)) {
        printf("QuicPcpInitialize failed, 0x%x\n", Status);
        goto Error;
    }

    printf("Sending MAP request...\n");
    Status = QuicPcpSendMapRequest(PcpContext, PcpNonce, nullptr, 1234, 360000);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }
    QuicSleep(1000);

    printf("Sending (delete) MAP request...\n");
    Status = QuicPcpSendMapRequest(PcpContext, PcpNonce, nullptr, 1234, 0);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }
    QuicSleep(1000);

    ErrorCode = 1;

Error:

    if (PcpContext) {
        QuicPcpUninitialize(PcpContext);
    }
    QuicDataPathUninitialize(Datapath);
    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    return ErrorCode;
}
