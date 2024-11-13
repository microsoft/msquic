/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC XDP Datapath Implementation (User Mode)

--*/

#define _CRT_SECURE_NO_WARNINGS 1 // TODO - Remove

#include "datapath_raw_xdp_wincommon.h"

#ifdef QUIC_CLOG
#include "datapath_raw_xdp_winkernel.c.clog.h"
#endif

QUIC_STATUS
CxPlatGetRssQueueProcessors(
    _In_ XDP_DATAPATH* Xdp,
    _In_ uint32_t InterfaceIndex,
    _Inout_ uint16_t* Count,
    _Out_writes_to_(*Count, *Count) uint32_t* Queues
    )
{
    UNREFERENCED_PARAMETER(Xdp);
    UNREFERENCED_PARAMETER(InterfaceIndex);
    UNREFERENCED_PARAMETER(Count);
    UNREFERENCED_PARAMETER(Queues);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatXdpReadConfig(
    _Inout_ XDP_DATAPATH* Xdp
    )
{
    UNREFERENCED_PARAMETER(Xdp);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInterfaceInitialize(
    _In_ XDP_DATAPATH* Xdp,
    _Inout_ XDP_INTERFACE* Interface,
    _In_ uint32_t ClientRecvContextLength
    )
{
    UNREFERENCED_PARAMETER(Xdp);
    UNREFERENCED_PARAMETER(Interface);
    UNREFERENCED_PARAMETER(ClientRecvContextLength);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInitialize(
    _Inout_ CXPLAT_DATAPATH_RAW* Datapath,
    _In_ uint32_t ClientRecvContextLength,
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _In_opt_ const QUIC_EXECUTION_CONFIG* Config
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(ClientRecvContextLength);
    UNREFERENCED_PARAMETER(WorkerPool);
    UNREFERENCED_PARAMETER(Config);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CxPlatXdpExecute(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(State);
    return FALSE;
}

void
RawDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    UNREFERENCED_PARAMETER(Cqe);
}
