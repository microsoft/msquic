//
// Copyright(c) Microsoft Corporation.All rights reserved.
// Licensed under the MIT License.
//
//
// Module Name:
//
//    ndioctl.h
//
// Abstract:
//
//    NetworkDirect Service Provider IOCTL definitions
//
// Environment:
//
//    User mode and kernel mode
//


#ifndef _NDIOCTL_H_
#define _NDIOCTL_H_

#pragma once

#include <ws2def.h>
#include <ws2ipdef.h>
#include <limits.h>
#include <ifdef.h>
#include "nddef.h"

#define ND_IOCTL_VERSION    1

#pragma warning(push)
#pragma warning(disable:4201)

typedef enum _ND_MAPPING_TYPE {
    NdMapIoSpace,
    NdMapMemory,
    NdMapMemoryCoallesce,
    NdMapPages,
    NdMapPagesCoallesce,
    NdUnmapIoSpace,
    NdUnmapMemory,
    NdMaximumMapType
} ND_MAPPING_TYPE;

typedef enum _ND_CACHING_TYPE {
    NdNonCached = 0,    // MmNonCached
    NdCached = 1,       // MmCached
    NdWriteCombined = 2,// MmWriteCombined
    NdMaximumCacheType
} ND_CACHING_TYPE;

typedef enum _ND_ACCESS_TYPE {
    NdReadAccess = 0,   // IoReadAccess
    NdWriteAccess = 1,  // IoWriteAccess
    NdModifyAccess = 2  // IoModifyAccess
} ND_ACCESS_TYPE;

typedef struct _ND_MAP_IO_SPACE {
    ND_MAPPING_TYPE MapType;
    ND_CACHING_TYPE CacheType;
    ULONG           CbLength;
} ND_MAP_IO_SPACE;

typedef struct _ND_MAP_MEMORY {
    ND_MAPPING_TYPE MapType;
    ND_ACCESS_TYPE  AccessType;
    UINT64          Address;
    ULONG           CbLength;
} ND_MAP_MEMORY;

typedef struct _ND_MAPPING_ID {
    ND_MAPPING_TYPE MapType;
    UINT64          Id;
} ND_MAPPING_ID;

typedef struct _NDK_MAP_PAGES {
    ND_MAP_MEMORY   Header;
    ULONG           CbLogicalPageAddressesOffset;
} NDK_MAP_PAGES;

typedef union _ND_MAPPING {
    ND_MAPPING_TYPE MapType;
    ND_MAP_IO_SPACE MapIoSpace;
    ND_MAP_MEMORY   MapMemory;
    ND_MAPPING_ID   MappingId;
    NDK_MAP_PAGES   MapPages;
} ND_MAPPING;

typedef struct _ND_MAPPING_RESULT {
    UINT64  Id;
    UINT64  Information;
} ND_MAPPING_RESULT;

typedef struct _ND_RESOURCE_DESCRIPTOR {
    UINT64              Handle;
    ULONG               CeMappingResults;
    ULONG               CbMappingResultsOffset;
} ND_RESOURCE_DESCRIPTOR;

typedef struct _ND_HANDLE {
    ULONG   Version;
    ULONG   Reserved;
    UINT64  Handle;
} ND_HANDLE;

typedef struct _ND_RESOLVE_ADDRESS {
    ULONG           Version;
    ULONG           Reserved;
    SOCKADDR_INET   Address;
} ND_RESOLVE_ADDRESS;

typedef struct _ND_OPEN_ADAPTER {
    ULONG       Version;
    ULONG       Reserved;
    ULONG       CeMappingCount;
    ULONG       CbMappingsOffset;
    UINT64      AdapterId;
} ND_OPEN_ADAPTER;

typedef struct _ND_ADAPTER_QUERY {
    ULONG   Version;
    ULONG   InfoVersion;
    UINT64  AdapterHandle;
} ND_ADAPTER_QUERY;

typedef struct _ND_CREATE_CQ {
    ULONG           Version;
    ULONG           QueueDepth;
    ULONG           CeMappingCount;
    ULONG           CbMappingsOffset;
    UINT64          AdapterHandle;
    GROUP_AFFINITY  Affinity;
} ND_CREATE_CQ;

typedef struct _ND_CREATE_SRQ {
    ULONG           Version;
    ULONG           QueueDepth;
    ULONG           CeMappingCount;
    ULONG           CbMappingsOffset;
    ULONG           MaxRequestSge;
    ULONG           NotifyThreshold;
    UINT64          PdHandle;
    GROUP_AFFINITY  Affinity;
} ND_CREATE_SRQ;

typedef struct _ND_CREATE_QP_HDR {
    ULONG       Version;
    ULONG       CbMaxInlineData;
    ULONG       CeMappingCount;
    ULONG       CbMappingsOffset;
    ULONG       InitiatorQueueDepth;
    ULONG       MaxInitiatorRequestSge;
    UINT64      ReceiveCqHandle;
    UINT64      InitiatorCqHandle;
    UINT64      PdHandle;
} ND_CREATE_QP_HDR;

typedef struct _ND_CREATE_QP {
    ND_CREATE_QP_HDR    Header;
    ULONG               ReceiveQueueDepth;
    ULONG               MaxReceiveRequestSge;
} ND_CREATE_QP;

typedef struct _ND_CREATE_QP_WITH_SRQ {
    ND_CREATE_QP_HDR    Header;
    UINT64              SrqHandle;
} ND_CREATE_QP_WITH_SRQ;

typedef struct _ND_SRQ_MODIFY {
    ULONG       Version;
    ULONG       QueueDepth;
    ULONG       CeMappingCount;
    ULONG       CbMappingsOffset;
    ULONG       NotifyThreshold;
    ULONG       Reserved;
    UINT64      SrqHandle;
} ND_SRQ_MODIFY;

typedef struct _ND_CQ_MODIFY {
    ULONG       Version;
    ULONG       QueueDepth;
    ULONG       CeMappingCount;
    ULONG       CbMappingsOffset;
    UINT64      CqHandle;
} ND_CQ_MODIFY;

typedef struct _ND_CQ_NOTIFY {
    ULONG   Version;
    ULONG   Type;
    UINT64  CqHandle;
} ND_CQ_NOTIFY;

typedef struct _ND_MR_REGISTER_HDR {
    ULONG   Version;
    ULONG   Flags;
    UINT64  CbLength;
    UINT64  TargetAddress;
    UINT64  MrHandle;
} ND_MR_REGISTER_HDR;

typedef struct _ND_MR_REGISTER {
    ND_MR_REGISTER_HDR  Header;
    UINT64              Address;
} ND_MR_REGISTER;

typedef struct _ND_BIND {
    ULONG           Version;
    ULONG           Reserved;
    UINT64          Handle;
    SOCKADDR_INET   Address;
} ND_BIND, NDV_PARTITION_UNBIND_ADDRESS;

typedef struct _ND_READ_LIMITS {
    ULONG   Inbound;
    ULONG   Outbound;
} ND_READ_LIMITS;

typedef struct _ND_CONNECT {
    ULONG               Version;
    ULONG               Reserved;
    ND_READ_LIMITS      ReadLimits;
    ULONG               CbPrivateDataLength;
    ULONG               CbPrivateDataOffset;
    UINT64              ConnectorHandle;
    UINT64              QpHandle;
    SOCKADDR_INET       DestinationAddress;
    IF_PHYSICAL_ADDRESS DestinationHwAddress;
} ND_CONNECT;

typedef struct _ND_ACCEPT {
    ULONG           Version;
    ULONG           Reserved;
    ND_READ_LIMITS  ReadLimits;
    ULONG           CbPrivateDataLength;
    ULONG           CbPrivateDataOffset;
    UINT64          ConnectorHandle;
    UINT64          QpHandle;
} ND_ACCEPT;

typedef struct _ND_REJECT {
    ULONG   Version;
    ULONG   Reserved;
    ULONG   CbPrivateDataLength;
    ULONG   CbPrivateDataOffset;
    UINT64  ConnectorHandle;
} ND_REJECT;

typedef struct _ND_LISTEN {
    ULONG   Version;
    ULONG   Backlog;
    UINT64  ListenerHandle;
} ND_LISTEN;

typedef struct _ND_GET_CONNECTION_REQUEST {
    ULONG   Version;
    ULONG   Reserved;
    UINT64  ListenerHandle;
    UINT64  ConnectorHandle;
} ND_GET_CONNECTION_REQUEST;


#if defined(_DDK_DRIVER_) || defined(_NTIFS_)

typedef enum _NDV_MMIO_TYPE {
    NdPartitionKernelVirtual,
    NdPartitionSystemPhysical,
    NdPartitionGuestPhysical,
    NdMaximumMmioType
} NDV_MMIO_TYPE;

typedef struct _NDV_RESOLVE_ADAPTER_ID {
    ULONG               Version;
    IF_PHYSICAL_ADDRESS HwAddress;
} NDV_RESOLVE_ADAPTER_ID;

typedef struct _NDV_PARTITION_CREATE {
    ULONG               Version;
    NDV_MMIO_TYPE       MmioType;
    UINT64              AdapterId;
    UINT64              XmitCap;
} NDV_PARTITION_CREATE;

typedef struct _NDV_PARTITION_BIND_LUID {
    ULONG               Version;
    ULONG               Reserved;
    UINT64              PartitionHandle;
    IF_PHYSICAL_ADDRESS HwAddress;
    IF_LUID             Luid;
} NDV_PARTITION_BIND_LUID;

typedef struct _NDV_PARTITION_BIND_ADDRESS {
    ULONG               Version;
    ULONG               Reserved;
    UINT64              PartitionHandle;
    SOCKADDR_INET       Address;
    IF_PHYSICAL_ADDRESS GuestHwAddress;
    IF_PHYSICAL_ADDRESS HwAddress;
} NDV_PARTITION_BIND_ADDRESS;

typedef struct _NDK_MR_REGISTER {
    ND_MR_REGISTER_HDR  Header;
    ULONG               CbLogicalPageAddressesOffset;
} NDK_MR_REGISTER;

typedef struct _NDK_BIND {
    ND_BIND Header;
    LUID    AuthenticationId;
    BOOLEAN IsAdmin;
} NDK_BIND;

#endif  // _DDK_DRIVER_

#pragma warning(pop)

#define ND_FUNCTION(r_, i_)    (r_ << 6 | i_)
#define IOCTL_ND(r_, i_)   CTL_CODE( FILE_DEVICE_NETWORK, ND_FUNCTION(r_, i_), METHOD_BUFFERED, FILE_ANY_ACCESS )

#define ND_FUNCTION_FROM_CTL_CODE(ctrlCode_)     ((ctrlCode_ >> 2) & 0xFFF)
#define ND_RESOURCE_FROM_CTL_CODE(ctrlCode_)     (ND_FUNCTION_FROM_CTL_CODE(ctrlCode_) >> 6)
#define ND_OPERATION_FROM_CTRL_CODE(ctrlCode_)   (ND_FUNCTION_FROM_CTL_CODE(ctrlCode_) & 0x3F)

#define ND_DOS_DEVICE_NAME L"\\DosDevices\\Global\\NetworkDirect"
#define ND_WIN32_DEVICE_NAME L"\\\\.\\NetworkDirect"

typedef enum _ND_RESOURCE_TYPE {
    NdProvider = 0,
    NdAdapter = 1,
    NdPd = 2,
    NdCq = 3,
    NdMr = 4,
    NdMw = 5,
    NdSrq = 6,
    NdConnector = 7,
    NdListener = 8,
    NdQp = 9,
    NdVirtualPartition = 10,
    ND_RESOURCE_TYPE_COUNT
} ND_RESOURCE_TYPE;

#define ND_OPERATION_COUNT 14

#define IOCTL_ND_PROVIDER(i_)           IOCTL_ND(NdProvider, i_)
#define IOCTL_ND_ADAPTER(i_)            IOCTL_ND(NdAdapter, i_)
#define IOCTL_ND_PD(i_)                 IOCTL_ND(NdPd, i_)
#define IOCTL_ND_CQ(i_)                 IOCTL_ND(NdCq, i_)
#define IOCTL_ND_MR(i_)                 IOCTL_ND(NdMr, i_)
#define IOCTL_ND_MW(i_)                 IOCTL_ND(NdMw, i_)
#define IOCTL_ND_SRQ(i_)                IOCTL_ND(NdSrq, i_)
#define IOCTL_ND_CONNECTOR(i_)          IOCTL_ND(NdConnector, i_)
#define IOCTL_ND_LISTENER(i_)           IOCTL_ND(NdListener, i_)
#define IOCTL_ND_QP(i_)                 IOCTL_ND(NdQp, i_)
#define IOCTL_ND_VIRTUAL_PARTITION(i_)  IOCTL_ND(NdVirtualPartition, i_)

// Provider IOCTLs
#define IOCTL_ND_PROVIDER_INIT                      IOCTL_ND_PROVIDER( 0 )
#define IOCTL_ND_PROVIDER_BIND_FILE                 IOCTL_ND_PROVIDER( 1 )
#define IOCTL_ND_PROVIDER_QUERY_ADDRESS_LIST        IOCTL_ND_PROVIDER( 2 )
#define IOCTL_ND_PROVIDER_RESOLVE_ADDRESS           IOCTL_ND_PROVIDER( 3 )
#define IOCTL_ND_PROVIDER_MAX_OPERATION                                4

// Adapter IOCTLs
#define IOCTL_ND_ADAPTER_OPEN                       IOCTL_ND_ADAPTER( 0 )
#define IOCTL_ND_ADAPTER_CLOSE                      IOCTL_ND_ADAPTER( 1 )
#define IOCTL_ND_ADAPTER_QUERY                      IOCTL_ND_ADAPTER( 2 )
#define IOCTL_ND_ADAPTER_QUERY_ADDRESS_LIST         IOCTL_ND_ADAPTER( 3 )
#define IOCTL_ND_ADAPTER_MAX_OPERATION                                4

// Protection Domain IOCTLs
#define IOCTL_ND_PD_CREATE                          IOCTL_ND_PD( 0 )
#define IOCTL_ND_PD_FREE                            IOCTL_ND_PD( 1 )
#define IOCTL_ND_PD_MAX_OPERATION                                2

// Completion Queue IOCTLs
#define IOCTL_ND_CQ_CREATE                          IOCTL_ND_CQ( 0 )
#define IOCTL_ND_CQ_FREE                            IOCTL_ND_CQ( 1 )
#define IOCTL_ND_CQ_CANCEL_IO                       IOCTL_ND_CQ( 2 )
#define IOCTL_ND_CQ_GET_AFFINITY                    IOCTL_ND_CQ( 3 )
#define IOCTL_ND_CQ_MODIFY                          IOCTL_ND_CQ( 4 )
#define IOCTL_ND_CQ_NOTIFY                          IOCTL_ND_CQ( 5 )
#define IOCTL_ND_CQ_MAX_OPERATION                                6

// Memory Region IOCTLs
#define IOCTL_ND_MR_CREATE                          IOCTL_ND_MR( 0 )
#define IOCTL_ND_MR_FREE                            IOCTL_ND_MR( 1 )
#define IOCTL_ND_MR_CANCEL_IO                       IOCTL_ND_MR( 2 )
#define IOCTL_ND_MR_REGISTER                        IOCTL_ND_MR( 3 )
#define IOCTL_ND_MR_DEREGISTER                      IOCTL_ND_MR( 4 )
#define IOCTL_NDK_MR_REGISTER                       IOCTL_ND_MR( 5 )
#define IOCTL_ND_MR_MAX_OPERATION                                6

// Memory Window IOCTLs
#define IOCTL_ND_MW_CREATE                          IOCTL_ND_MW( 0 )
#define IOCTL_ND_MW_FREE                            IOCTL_ND_MW( 1 )
#define IOCTL_ND_MW_MAX_OPERATION                                2

// Shared Receive Queue IOCTLs
#define IOCTL_ND_SRQ_CREATE                         IOCTL_ND_SRQ( 0 )
#define IOCTL_ND_SRQ_FREE                           IOCTL_ND_SRQ( 1 )
#define IOCTL_ND_SRQ_CANCEL_IO                      IOCTL_ND_SRQ( 2 )
#define IOCTL_ND_SRQ_GET_AFFINITY                   IOCTL_ND_SRQ( 3 )
#define IOCTL_ND_SRQ_MODIFY                         IOCTL_ND_SRQ( 4 )
#define IOCTL_ND_SRQ_NOTIFY                         IOCTL_ND_SRQ( 5 )
#define IOCTL_ND_SRQ_MAX_OPERATION                                6

// Connector IOCTLs
#define IOCTL_ND_CONNECTOR_CREATE                   IOCTL_ND_CONNECTOR( 0 )
#define IOCTL_ND_CONNECTOR_FREE                     IOCTL_ND_CONNECTOR( 1 )
#define IOCTL_ND_CONNECTOR_CANCEL_IO                IOCTL_ND_CONNECTOR( 2 )
#define IOCTL_ND_CONNECTOR_BIND                     IOCTL_ND_CONNECTOR( 3 )
#define IOCTL_ND_CONNECTOR_CONNECT                  IOCTL_ND_CONNECTOR( 4 )
#define IOCTL_ND_CONNECTOR_COMPLETE_CONNECT         IOCTL_ND_CONNECTOR( 5 )
#define IOCTL_ND_CONNECTOR_ACCEPT                   IOCTL_ND_CONNECTOR( 6 )
#define IOCTL_ND_CONNECTOR_REJECT                   IOCTL_ND_CONNECTOR( 7 )
#define IOCTL_ND_CONNECTOR_GET_READ_LIMITS          IOCTL_ND_CONNECTOR( 8 )
#define IOCTL_ND_CONNECTOR_GET_PRIVATE_DATA         IOCTL_ND_CONNECTOR( 9 )
#define IOCTL_ND_CONNECTOR_GET_PEER_ADDRESS         IOCTL_ND_CONNECTOR( 10 )
#define IOCTL_ND_CONNECTOR_GET_ADDRESS              IOCTL_ND_CONNECTOR( 11 )
#define IOCTL_ND_CONNECTOR_NOTIFY_DISCONNECT        IOCTL_ND_CONNECTOR( 12 )
#define IOCTL_ND_CONNECTOR_DISCONNECT               IOCTL_ND_CONNECTOR( 13 )
#define IOCTL_ND_CONNECTOR_MAX_OPERATION                                14

// Listener IOCTLs
#define IOCTL_ND_LISTENER_CREATE                    IOCTL_ND_LISTENER( 0 )
#define IOCTL_ND_LISTENER_FREE                      IOCTL_ND_LISTENER( 1 )
#define IOCTL_ND_LISTENER_CANCEL_IO                 IOCTL_ND_LISTENER( 2 )
#define IOCTL_ND_LISTENER_BIND                      IOCTL_ND_LISTENER( 3 )
#define IOCTL_ND_LISTENER_LISTEN                    IOCTL_ND_LISTENER( 4 )
#define IOCTL_ND_LISTENER_GET_ADDRESS               IOCTL_ND_LISTENER( 5 )
#define IOCTL_ND_LISTENER_GET_CONNECTION_REQUEST    IOCTL_ND_LISTENER( 6 )
#define IOCTL_ND_LISTENER_MAX_OPERATION                                7

// Queue Pair IOCTLs
#define IOCTL_ND_QP_CREATE                          IOCTL_ND_QP( 0 )
#define IOCTL_ND_QP_CREATE_WITH_SRQ                 IOCTL_ND_QP( 1 )
#define IOCTL_ND_QP_FREE                            IOCTL_ND_QP( 2 )
#define IOCTL_ND_QP_FLUSH                           IOCTL_ND_QP( 3 )
#define IOCTL_ND_QP_MAX_OPERATION                                4

// Kernel-mode only IOCTLs (IRP_MJ_INTERNAL_DEVICE_CONTROL)
#define IOCTL_NDV_PARTITION_RESOLVE_ADAPTER_ID      IOCTL_ND_VIRTUAL_PARTITION( 0 )
#define IOCTL_NDV_PARTITION_CREATE                  IOCTL_ND_VIRTUAL_PARTITION( 1 )
#define IOCTL_NDV_PARTITION_FREE                    IOCTL_ND_VIRTUAL_PARTITION( 2 )
#define IOCTL_NDV_PARTITION_BIND                    IOCTL_ND_VIRTUAL_PARTITION( 3 )
#define IOCTL_NDV_PARTITION_UNBIND                  IOCTL_ND_VIRTUAL_PARTITION( 4 )
#define IOCTL_NDV_PARTITION_BIND_LUID               IOCTL_ND_VIRTUAL_PARTITION( 5 )
#define IOCTL_NDV_PARTITION_MAX_OPERATION                                       6


#if defined(_DDK_DRIVER_) || defined(_NTIFS_)

__inline NTSTATUS
NdValidateMemoryMapping(
    __in const ND_MAPPING* pMapping,
    ND_ACCESS_TYPE AccessType,
    ULONG CbLength
)
{
    if (pMapping->MapType != NdMapMemory && pMapping->MapType != NdMapPages)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pMapping->MapMemory.AccessType != AccessType ||
        pMapping->MapMemory.CbLength < CbLength)
    {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

__inline NTSTATUS
NdValidateCoallescedMapping(
    __in const ND_MAPPING* pMapping,
    ND_ACCESS_TYPE AccessType,
    ULONG CbLength
)
{
    if (pMapping->MapType != NdMapMemoryCoallesce && pMapping->MapType != NdMapPagesCoallesce)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pMapping->MapMemory.AccessType != AccessType ||
        BYTE_OFFSET(pMapping->MapMemory.Address) + pMapping->MapMemory.CbLength > PAGE_SIZE ||
        pMapping->MapMemory.CbLength != CbLength)
    {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

__inline NTSTATUS
NdValidateIoSpaceMapping(
    __in const ND_MAPPING* pMapping,
    ND_CACHING_TYPE CacheType,
    ULONG CbLength
)
{
    if (pMapping->MapType != NdMapIoSpace ||
        pMapping->MapIoSpace.CacheType != CacheType ||
        pMapping->MapIoSpace.CbLength != CbLength)
    {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

__inline void
NdThunkAdapterInfo(
    __out ND2_ADAPTER_INFO32* pInfo32,
    __in const ND2_ADAPTER_INFO* pInfo
)
{
    pInfo32->InfoVersion = pInfo->InfoVersion;
    pInfo32->VendorId = pInfo->VendorId;
    pInfo32->DeviceId = pInfo->DeviceId;
    pInfo32->AdapterId = pInfo->AdapterId;
    pInfo32->MaxRegistrationSize = (ULONG)(min(ULONG_MAX, pInfo->MaxRegistrationSize));
    pInfo32->MaxWindowSize = (ULONG)(min(ULONG_MAX, pInfo->MaxWindowSize));
    pInfo32->MaxInitiatorSge = pInfo->MaxInitiatorSge;
    pInfo32->MaxReceiveSge = pInfo->MaxReceiveSge;
    pInfo32->MaxReadSge = pInfo->MaxReadSge;
    pInfo32->MaxTransferLength = pInfo->MaxTransferLength;
    pInfo32->MaxInlineDataSize = pInfo->MaxInlineDataSize;
    pInfo32->MaxInboundReadLimit = pInfo->MaxInboundReadLimit;
    pInfo32->MaxOutboundReadLimit = pInfo->MaxOutboundReadLimit;
    pInfo32->MaxReceiveQueueDepth = pInfo->MaxReceiveQueueDepth;
    pInfo32->MaxInitiatorQueueDepth = pInfo->MaxInitiatorQueueDepth;
    pInfo32->MaxSharedReceiveQueueDepth = pInfo->MaxSharedReceiveQueueDepth;
    pInfo32->MaxCompletionQueueDepth = pInfo->MaxCompletionQueueDepth;
    pInfo32->InlineRequestThreshold = pInfo->InlineRequestThreshold;
    pInfo32->LargeRequestThreshold = pInfo->LargeRequestThreshold;
    pInfo32->MaxCallerData = pInfo->MaxCallerData;
    pInfo32->MaxCalleeData = pInfo->MaxCalleeData;
    pInfo32->AdapterFlags = pInfo->AdapterFlags;
}

#endif  // _DDK_DRIVER_

#endif // _NDSPI_H_
