/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath Implementation (User Mode)

--*/

#include "platform_internal.h"

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

void
CxPlatDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    if (CXPLAT_CQE_TYPE_XDP_SHUTDOWN <= CxPlatCqeType(Cqe)) {
        RawDataPathProcessCqe(Cqe);
    } else {
        DataPathProcessCqe(Cqe);
    }
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
