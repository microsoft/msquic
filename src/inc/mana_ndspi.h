#pragma once

#ifndef _MANA_NDSPI_H_
#define _MANA_NDSPI_H_

#include <winsock2.h>
#include <unknwn.h>
#include "ndstatus.h"
#include "nddef.h"

typedef enum _ND2_MANA_REQUEST_TYPE {
    Nd2ManaRequestTypeSend,
    Nd2ManaRequestTypeBind,
    Nd2ManaRequestTypeInvalidate,
    Nd2ManaRequestTypeRead,
    Nd2ManaRequestTypeWrite,
    Nd2ManaRequestTypeRecv = 1 << 7,
    Nd2ManaRequestTypeRecvWithInvalidate,
    Nd2ManaRequestTypeRecvWithImmediate,
    Nd2ManaRequestTypeRecvRdmaWithImmediate,
} ND2_MANA_REQUEST_TYPE;

typedef struct _ND2_MANA_RESULT {
    HRESULT                 Status;
    ULONG                   BytesTransferred;
    VOID*                   QueuePairContext;
    VOID*                   RequestContext;
    ND2_MANA_REQUEST_TYPE   RequestType;
    UINT32                  ImmediateDataOrRKey;
} ND2_MANA_RESULT;

//
// Completion Queue
//
#undef INTERFACE
#define INTERFACE IND2ManaCompletionQueue

// {28925856-4FCC-4479-915C-034426A50B9E}
DEFINE_GUID(IID_IND2ManaCompletionQueue,
    0x28925856, 0x4fcc, 0x4479, 0x91, 0x5c, 0x3, 0x44, 0x26, 0xa5, 0xb, 0x9e);

DECLARE_INTERFACE_(IND2ManaCompletionQueue, IND2CompletionQueue)
{
    // *** IUnknown methods ***
    IFACEMETHOD(QueryInterface)(
        THIS_
        REFIID riid,
        __deref_out LPVOID* ppvObj
        ) PURE;

    IFACEMETHOD_(ULONG, AddRef)(
        THIS
        ) PURE;

    IFACEMETHOD_(ULONG, Release)(
        THIS
        ) PURE;

    // *** IND2Overlapped methods ***
    IFACEMETHOD(CancelOverlappedRequests)(
        THIS
        ) PURE;

    IFACEMETHOD(GetOverlappedResult)(
        THIS_
        __in OVERLAPPED* pOverlapped,
        BOOL wait
        ) PURE;

    // *** IND2CompletionQueue methods ***
    STDMETHOD(GetNotifyAffinity)(
        THIS_
        __out USHORT* pGroup,
        __out KAFFINITY* pAffinity
        ) PURE;

    STDMETHOD(Resize)(
        THIS_
        ULONG queueDepth
        ) PURE;

    STDMETHOD(Notify)(
        THIS_
        ULONG type,
        __inout OVERLAPPED* pOverlapped
        ) PURE;

    STDMETHOD_(ULONG, GetResults)(
        THIS_
        __out_ecount_part(nResults, return) ND2_RESULT results[],
        ULONG nResults
        ) PURE;

    // *** IND2ManaCompletionQueue methods ***
    STDMETHOD_(ULONG, GetManaResults)(
        THIS_
        __out_ecount_part(nResults, return) ND2_MANA_RESULT results[],
        ULONG nResults
        ) PURE;
};

//
// QueuePair
//
#undef INTERFACE
#define INTERFACE IND2ManaQueuePair

// {8B1811D5-52DD-4084-8119-15C11AB32FB9}
DEFINE_GUID(IID_IND2ManaQueuePair,
    0x8b1811d5, 0x52dd, 0x4084, 0x81, 0x19, 0x15, 0xc1, 0x1a, 0xb3, 0x2f, 0xb9);

DECLARE_INTERFACE_(IND2ManaQueuePair, IND2QueuePair)
{
    // *** IUnknown methods ***
    IFACEMETHOD(QueryInterface)(
        THIS_
        REFIID riid,
        __deref_out LPVOID* ppvObj
        ) PURE;

    IFACEMETHOD_(ULONG, AddRef)(
        THIS
        ) PURE;

    IFACEMETHOD_(ULONG, Release)(
        THIS
        ) PURE;

    // *** IND2QueuePair methods ***
    STDMETHOD(Flush)(
        THIS
        ) PURE;

    STDMETHOD(Send)(
        THIS_
        __in_opt VOID* requestContext,
        __in_ecount_opt(nSge) const ND2_SGE sge[],
        ULONG nSge,
        ULONG flags
        ) PURE;

    STDMETHOD(Receive)(
        THIS_
        __in_opt VOID* requestContext,
        __in_ecount_opt(nSge) const ND2_SGE sge[],
        ULONG nSge
        ) PURE;

    // RemoteToken available thorugh IND2Mw::GetRemoteToken.
    STDMETHOD(Bind)(
        THIS_
        __in_opt VOID* requestContext,
        __in IUnknown* pMemoryRegion,
        __inout IUnknown* pMemoryWindow,
        __in_bcount(cbBuffer) const VOID* pBuffer,
        SIZE_T cbBuffer,
        ULONG flags
        ) PURE;

    STDMETHOD(Invalidate)(
        THIS_
        __in_opt VOID* requestContext,
        __in IUnknown* pMemoryWindow,
        ULONG flags
        ) PURE;

    STDMETHOD(Read)(
        THIS_
        __in_opt VOID* requestContext,
        __in_ecount_opt(nSge) const ND2_SGE sge[],
        ULONG nSge,
        UINT64 remoteAddress,
        UINT32 remoteToken,
        ULONG flags
        ) PURE;

    STDMETHOD(Write)(
        THIS_
        __in_opt VOID* requestContext,
        __in_ecount_opt(nSge) const ND2_SGE sge[],
        ULONG nSge,
        UINT64 remoteAddress,
        UINT32 remoteToken,
        ULONG flags
        ) PURE;

    // *** IND2ManaQueuePair methods ***
    STDMETHOD(SendWithImmediate)(
        THIS_
        __in_opt VOID* requestContext,
        __in_ecount_opt(nSge) const ND2_SGE sge[],
        ULONG nSge,
        ULONG flags,
        UINT32 immediateData
        ) PURE;

    STDMETHOD(WriteWithImmediate)(
        THIS_
        __in_opt VOID* requestContext,
        __in_ecount_opt(nSge) const ND2_SGE sge[],
        ULONG nSge,
        UINT64 remoteAddress,
        UINT32 remoteToken,
        ULONG flags,
        UINT32 immediateData
        ) PURE;
};

#endif /* _MANA_NDSPI_H_ */
