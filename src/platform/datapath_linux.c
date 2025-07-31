/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath Implementation (User Mode)

--*/

#include "platform_internal.h"
#include "datapath_linux.h"

#ifdef QUIC_CLOG
#include "datapath_linux.c.clog.h"
#endif

QUIC_STATUS
CxPlatSocketUpdateQeo(
    _In_ CXPLAT_SOCKET* Socket,
    _In_reads_(OffloadCount)
        const CXPLAT_QEO_CONNECTION* Offloads,
    _In_ uint32_t OffloadCount
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Offloads);
    UNREFERENCED_PARAMETER(OffloadCount);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatUpdateRoute(
    _Inout_ CXPLAT_ROUTE* DstRoute,
    _In_ CXPLAT_ROUTE* SrcRoute
    )
{
    if (SrcRoute->DatapathType == CXPLAT_DATAPATH_TYPE_RAW ||
        (SrcRoute->DatapathType == CXPLAT_DATAPATH_TYPE_UNKNOWN &&
        !IS_LOOPBACK(SrcRoute->RemoteAddress))) {
        RawUpdateRoute(DstRoute, SrcRoute);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
DataPathUpdateConfig(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ QUIC_GLOBAL_EXECUTION_CONFIG * Config
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(Config);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_DATAPATH_FEATURES
DataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return Datapath->Features;
}

BOOLEAN
DataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return !!(Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
DataPathUpdatePollingIdleTimeout(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t PollingIdleTimeoutUs
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(PollingIdleTimeoutUs);
}

void
CxPlatDataPathCalculateFeatureSupport(
    _Inout_ CXPLAT_DATAPATH* Datapath
    )
{
#ifdef UDP_SEGMENT
    //
    // Open up two sockets and send with GSO and receive with GRO, and make sure
    // everything **actually** works, so that we can be sure we can leverage
    // GRO.
    //
    int SendSocket = INVALID_SOCKET, RecvSocket = INVALID_SOCKET;
    struct sockaddr_in RecvAddr = {0}, RecvAddr2 = {0};
    socklen_t RecvAddrSize = sizeof(RecvAddr), RecvAddr2Size = sizeof(RecvAddr2);
    int PktInfoEnabled = 1, TosEnabled = 1, GroEnabled = 1;
    uint8_t Buffer[8 * 1476] = {0};
    struct iovec IoVec;
    IoVec.iov_base = Buffer;
    IoVec.iov_len = sizeof(Buffer);
    char SendControlBuffer[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(uint16_t))] = {0};
    struct msghdr SendMsg = {0};
    SendMsg.msg_name = &RecvAddr;
    SendMsg.msg_namelen = RecvAddrSize;
    SendMsg.msg_iov = &IoVec;
    SendMsg.msg_iovlen = 1;
    SendMsg.msg_control = SendControlBuffer;
    SendMsg.msg_controllen = sizeof(SendControlBuffer);
    struct cmsghdr *CMsg = CMSG_FIRSTHDR(&SendMsg);
    CMsg->cmsg_level = IPPROTO_IP;
    CMsg->cmsg_type = IP_TOS;
    CMsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int*)CMSG_DATA(CMsg) = 0x1;
    CMsg = CMSG_NXTHDR(&SendMsg, CMsg);
    CMsg->cmsg_level = SOL_UDP;
    CMsg->cmsg_type = UDP_SEGMENT;
    CMsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    *((uint16_t*)CMSG_DATA(CMsg)) = 1476;
    RecvAddr.sin_family = AF_INET;
    RecvAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    char RecvControlBuffer[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};
    struct msghdr RecvMsg = {0};
    RecvMsg.msg_name = &RecvAddr2;
    RecvMsg.msg_namelen = RecvAddr2Size;
    RecvMsg.msg_iov = &IoVec;
    RecvMsg.msg_iovlen = 1;
    RecvMsg.msg_control = RecvControlBuffer;
    RecvMsg.msg_controllen = sizeof(RecvControlBuffer);
#define VERIFY(X) if (!(X)) { goto Error; }
    SendSocket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    VERIFY(SendSocket != INVALID_SOCKET)
    RecvSocket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    VERIFY(RecvSocket != INVALID_SOCKET)
    VERIFY(setsockopt(SendSocket, IPPROTO_IP, IP_PKTINFO, &PktInfoEnabled, sizeof(PktInfoEnabled)) != SOCKET_ERROR)
    VERIFY(setsockopt(RecvSocket, IPPROTO_IP, IP_PKTINFO, &PktInfoEnabled, sizeof(PktInfoEnabled)) != SOCKET_ERROR)
    VERIFY(setsockopt(SendSocket, IPPROTO_IP, IP_RECVTOS, &TosEnabled, sizeof(TosEnabled)) != SOCKET_ERROR)
    VERIFY(setsockopt(RecvSocket, IPPROTO_IP, IP_RECVTOS, &TosEnabled, sizeof(TosEnabled)) != SOCKET_ERROR)
    VERIFY(bind(RecvSocket, (struct sockaddr*)&RecvAddr, RecvAddrSize) != SOCKET_ERROR)
#ifdef UDP_GRO
    VERIFY(setsockopt(RecvSocket, SOL_UDP, UDP_GRO, &GroEnabled, sizeof(GroEnabled)) != SOCKET_ERROR)
#endif
    VERIFY(getsockname(RecvSocket, (struct sockaddr*)&RecvAddr, &RecvAddrSize) != SOCKET_ERROR)
    VERIFY(connect(SendSocket, (struct sockaddr*)&RecvAddr, RecvAddrSize) != SOCKET_ERROR)
    VERIFY(sendmsg(SendSocket, &SendMsg, 0) == sizeof(Buffer))
    //
    // We were able to at least send successfully, so indicate the send
    // segmentation feature as available.
    //
    Datapath->Features |= CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION;
#ifdef UDP_GRO
    VERIFY(recvmsg(RecvSocket, &RecvMsg, 0) == sizeof(Buffer))
    BOOLEAN FoundPKTINFO = FALSE, FoundTOS = FALSE, FoundGRO = FALSE;
    for (CMsg = CMSG_FIRSTHDR(&RecvMsg); CMsg != NULL; CMsg = CMSG_NXTHDR(&RecvMsg, CMsg)) {
        if (CMsg->cmsg_level == IPPROTO_IP) {
            if (CMsg->cmsg_type == IP_PKTINFO) {
                FoundPKTINFO = TRUE;
            } else if (CMsg->cmsg_type == IP_TOS) {
                CXPLAT_DBG_ASSERT_CMSG(CMsg, uint8_t);
                VERIFY(0x1 == *(uint8_t*)CMSG_DATA(CMsg))
                FoundTOS = TRUE;
            }
        } else if (CMsg->cmsg_level == IPPROTO_UDP) {
            if (CMsg->cmsg_type == UDP_GRO) {
                CXPLAT_DBG_ASSERT_CMSG(CMsg, uint16_t);
                VERIFY(1476 == *(uint16_t*)CMSG_DATA(CMsg))
                FoundGRO = TRUE;
            }
        }
    }
    VERIFY(FoundPKTINFO)
    VERIFY(FoundTOS)
    VERIFY(FoundGRO)
    //
    // We were able receive everything successfully so we can indicate the
    // receive coalescing feature as available.
    //
    Datapath->Features |= CXPLAT_DATAPATH_FEATURE_RECV_COALESCING;
#endif // UDP_GRO
Error:
    if (RecvSocket != INVALID_SOCKET) { close(RecvSocket); }
    if (SendSocket != INVALID_SOCKET) { close(SendSocket); }
#endif // UDP_SEGMENT

    Datapath->Features |= CXPLAT_DATAPATH_FEATURE_LOCAL_PORT_SHARING;
    Datapath->Features |= CXPLAT_DATAPATH_FEATURE_TTL;
    Datapath->Features |= CXPLAT_DATAPATH_FEATURE_SEND_DSCP;
    Datapath->Features |= CXPLAT_DATAPATH_FEATURE_RECV_DSCP;
}

QUIC_STATUS
CxPlatSocketConfigureRss(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ uint32_t SocketCount
    )
{
#ifdef SO_ATTACH_REUSEPORT_CBPF
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Result = 0;

    struct sock_filter BpfCode[] = {
        {BPF_LD | BPF_W | BPF_ABS, 0, 0, SKF_AD_OFF | SKF_AD_CPU}, // Load CPU number
        {BPF_ALU | BPF_MOD, 0, 0, SocketCount}, // MOD by SocketCount
        {BPF_RET | BPF_A, 0, 0, 0} // Return
    };

    struct sock_fprog BpfConfig = {0};
	BpfConfig.len = ARRAYSIZE(BpfCode);
    BpfConfig.filter = BpfCode;

    Result =
        setsockopt(
            SocketContext->SocketFd,
            SOL_SOCKET,
            SO_ATTACH_REUSEPORT_CBPF,
            (const void*)&BpfConfig,
            sizeof(BpfConfig));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "setsockopt(SO_ATTACH_REUSEPORT_CBPF) failed");
    }

    return Status;
#else
    UNREFERENCED_PARAMETER(SocketContext);
    UNREFERENCED_PARAMETER(SocketCount);
    return QUIC_STATUS_NOT_SUPPORTED;
#endif
}

void
CxPlatSocketHandleError(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ int ErrNum
    )
{
    CXPLAT_DBG_ASSERT(ErrNum != 0);

    QuicTraceEvent(
        DatapathErrorStatus,
        "[data][%p] ERROR, %u, %s.",
        SocketContext->Binding,
        ErrNum,
        "Socket error event");

    if (SocketContext->Binding->Type == CXPLAT_SOCKET_UDP) {
        //
        // Send unreachable notification to MsQuic if any related
        // errors were received.
        //
        if (ErrNum == ECONNREFUSED ||
            ErrNum == EHOSTUNREACH ||
            ErrNum == ENETUNREACH) {
            if (!SocketContext->Binding->PcpBinding) {
                SocketContext->Binding->Datapath->UdpHandlers.Unreachable(
                    SocketContext->Binding,
                    SocketContext->Binding->ClientContext,
                    &SocketContext->Binding->RemoteAddress);
            }
        }
    } else {
        if (!SocketContext->Binding->DisconnectIndicated) {
            SocketContext->Binding->DisconnectIndicated = TRUE;
            SocketContext->Binding->Datapath->TcpHandlers.Connect(
                SocketContext->Binding,
                SocketContext->Binding->ClientContext,
                FALSE);
        }
    }
}
