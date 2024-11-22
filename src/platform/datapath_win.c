/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath Implementation (User Mode)

--*/

#include "platform_internal.h"

#ifdef QUIC_CLOG
#include "datapath_winuser.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketUpdateQeo(
    _In_ CXPLAT_SOCKET* Socket,
    _In_reads_(OffloadCount)
        const CXPLAT_QEO_CONNECTION* Offloads,
    _In_ uint32_t OffloadCount
    )
{
    if (Socket->UseTcp || (Socket->RawSocketAvailable &&
        !IS_LOOPBACK(Offloads[0].Address))) {
        return RawSocketUpdateQeo(CxPlatSocketToRaw(Socket), Offloads, OffloadCount);
    }
    return QUIC_STATUS_NOT_SUPPORTED;
}

void
CxPlatDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    switch (CxPlatCqeType(Cqe)) {
    case CXPLAT_CQE_TYPE_SOCKET_IO: {
        DATAPATH_IO_SQE* Sqe =
            CONTAINING_RECORD(CxPlatCqeUserData(Cqe), DATAPATH_IO_SQE, DatapathSqe);
        if (Sqe->IoType == DATAPATH_XDP_IO_RECV || Sqe->IoType == DATAPATH_XDP_IO_SEND) {
            RawDataPathProcessCqe(Cqe);
        } else {
            DataPathProcessCqe(Cqe);
        }
        break;
    }
    case CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN: {
        RawDataPathProcessCqe(Cqe);
        break;
    }
    default: CXPLAT_DBG_ASSERT(FALSE); break;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatUpdateRoute(
    _Inout_ CXPLAT_ROUTE* DstRoute,
    _In_ CXPLAT_ROUTE* SrcRoute
    )
{
    if (SrcRoute->DatapathType == CXPLAT_DATAPATH_TYPE_RAW) {
        RawUpdateRoute(DstRoute, SrcRoute);
    }
    if (DstRoute->DatapathType != SrcRoute->DatapathType ||
        (DstRoute->State == RouteResolved &&
         DstRoute->Queue != SrcRoute->Queue)) {
        DstRoute->Queue = SrcRoute->Queue;
        DstRoute->DatapathType = SrcRoute->DatapathType;
    }
}
