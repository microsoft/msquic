/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    An "operation" is a single unit of work for a connection.

    Examples:
    -Handling an API call
    -Handling a timer that fired
    -Handling a received packet chain
    -Sending a flight of data

    An "operation queue" is a per-connection, multiple-producer, single-consumer
    queue of operations. Operations are pushed onto the queue by arbitrary
    application threads, datapath receive handlers, and so on. The queue is
    drained and processed by a single QUIC_WORKER thread. This worker thread
    is the only thread that touches the connection itself, which simplifies
    synchronization.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "operation.c.clog.h"
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicOperationQueueInitialize(
    _Inout_ QUIC_OPERATION_QUEUE* OperQ
    )
{
    OperQ->ActivelyProcessing = FALSE;
    CxPlatDispatchLockInitialize(&OperQ->Lock);
    CxPlatListInitializeHead(&OperQ->List);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicOperationQueueUninitialize(
    _In_ QUIC_OPERATION_QUEUE* OperQ
    )
{
    UNREFERENCED_PARAMETER(OperQ);
    CXPLAT_DBG_ASSERT(CxPlatListIsEmpty(&OperQ->List));
    CxPlatDispatchLockUninitialize(&OperQ->Lock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_OPERATION*
QuicOperationAlloc(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_OPERATION_TYPE Type
    )
{
    QUIC_OPERATION* Oper = (QUIC_OPERATION*)CxPlatPoolAlloc(&Worker->OperPool);
    if (Oper != NULL) {
#if DEBUG
        Oper->Link.Flink = NULL;
#endif
        Oper->Type = Type;
        Oper->FreeAfterProcess = TRUE;

        if (Oper->Type == QUIC_OPER_TYPE_API_CALL) {
            Oper->API_CALL.Context =
                (QUIC_API_CONTEXT*)CxPlatPoolAlloc(&Worker->ApiContextPool);
            if (Oper->API_CALL.Context == NULL) {
                CxPlatPoolFree(&Worker->OperPool, Oper);
                Oper = NULL;
            } else {
                Oper->API_CALL.Context->Status = NULL;
                Oper->API_CALL.Context->Completed = NULL;
            }
        }
    }
    return Oper;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicOperationFree(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_OPERATION* Oper
    )
{
#if DEBUG
    CXPLAT_DBG_ASSERT(Oper->Link.Flink == NULL);
#endif
    CXPLAT_DBG_ASSERT(Oper->FreeAfterProcess);
    if (Oper->Type == QUIC_OPER_TYPE_API_CALL) {
        QUIC_API_CONTEXT* ApiCtx = Oper->API_CALL.Context;
        if (ApiCtx->Type == QUIC_API_TYPE_CONN_START) {
            QuicConfigurationRelease(ApiCtx->CONN_START.Configuration);
            if (ApiCtx->CONN_START.ServerName != NULL) {
                CXPLAT_FREE(ApiCtx->CONN_START.ServerName, QUIC_POOL_SERVERNAME);
            }
        } else if (ApiCtx->Type == QUIC_API_TYPE_CONN_SET_CONFIGURATION) {
            QuicConfigurationRelease(ApiCtx->CONN_SET_CONFIGURATION.Configuration);
        } else if (ApiCtx->Type == QUIC_API_TYPE_CONN_SEND_RESUMPTION_TICKET) {
            if (ApiCtx->CONN_SEND_RESUMPTION_TICKET.ResumptionAppData != NULL) {
                CXPLAT_DBG_ASSERT(ApiCtx->CONN_SEND_RESUMPTION_TICKET.AppDataLength != 0);
                CXPLAT_FREE(ApiCtx->CONN_SEND_RESUMPTION_TICKET.ResumptionAppData, QUIC_POOL_APP_RESUMPTION_DATA);
            }
        } else if (ApiCtx->Type == QUIC_API_TYPE_STRM_START) {
            CXPLAT_DBG_ASSERT(ApiCtx->Completed == NULL);
            QuicStreamRelease(ApiCtx->STRM_START.Stream, QUIC_STREAM_REF_OPERATION);
        } else if (ApiCtx->Type == QUIC_API_TYPE_STRM_SHUTDOWN) {
            QuicStreamRelease(ApiCtx->STRM_SHUTDOWN.Stream, QUIC_STREAM_REF_OPERATION);
        } else if (ApiCtx->Type == QUIC_API_TYPE_STRM_SEND) {
            QuicStreamRelease(ApiCtx->STRM_SEND.Stream, QUIC_STREAM_REF_OPERATION);
        } else if (ApiCtx->Type == QUIC_API_TYPE_STRM_RECV_COMPLETE) {
            if (ApiCtx->STRM_RECV_COMPLETE.Stream) {
                QuicStreamRelease(ApiCtx->STRM_RECV_COMPLETE.Stream, QUIC_STREAM_REF_OPERATION);
            }
        } else if (ApiCtx->Type == QUIC_API_TYPE_STRM_RECV_SET_ENABLED) {
            QuicStreamRelease(ApiCtx->STRM_RECV_SET_ENABLED.Stream, QUIC_STREAM_REF_OPERATION);
        }
        CxPlatPoolFree(&Worker->ApiContextPool, ApiCtx);
    } else if (Oper->Type == QUIC_OPER_TYPE_FLUSH_STREAM_RECV) {
        QuicStreamRelease(Oper->FLUSH_STREAM_RECEIVE.Stream, QUIC_STREAM_REF_OPERATION);
    } else if (Oper->Type >= QUIC_OPER_TYPE_VERSION_NEGOTIATION) {
        if (Oper->STATELESS.Context != NULL) {
            QuicBindingReleaseStatelessOperation(Oper->STATELESS.Context, TRUE);
        }
    }
    CxPlatPoolFree(&Worker->OperPool, Oper);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicOperationEnqueue(
    _In_ QUIC_OPERATION_QUEUE* OperQ,
    _In_ QUIC_OPERATION* Oper
    )
{
    BOOLEAN StartProcessing;
    CxPlatDispatchLockAcquire(&OperQ->Lock);
#if DEBUG
    CXPLAT_DBG_ASSERT(Oper->Link.Flink == NULL);
#endif
    StartProcessing = CxPlatListIsEmpty(&OperQ->List) && !OperQ->ActivelyProcessing;
    CxPlatListInsertTail(&OperQ->List, &Oper->Link);
    CxPlatDispatchLockRelease(&OperQ->Lock);
    QuicPerfCounterIncrement(QUIC_PERF_COUNTER_CONN_OPER_QUEUED);
    QuicPerfCounterIncrement(QUIC_PERF_COUNTER_CONN_OPER_QUEUE_DEPTH);
    return StartProcessing;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicOperationEnqueueFront(
    _In_ QUIC_OPERATION_QUEUE* OperQ,
    _In_ QUIC_OPERATION* Oper
    )
{
    BOOLEAN StartProcessing;
    CxPlatDispatchLockAcquire(&OperQ->Lock);
#if DEBUG
    CXPLAT_DBG_ASSERT(Oper->Link.Flink == NULL);
#endif
    StartProcessing = CxPlatListIsEmpty(&OperQ->List) && !OperQ->ActivelyProcessing;
    CxPlatListInsertHead(&OperQ->List, &Oper->Link);
    CxPlatDispatchLockRelease(&OperQ->Lock);
    QuicPerfCounterIncrement(QUIC_PERF_COUNTER_CONN_OPER_QUEUED);
    QuicPerfCounterIncrement(QUIC_PERF_COUNTER_CONN_OPER_QUEUE_DEPTH);
    return StartProcessing;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_OPERATION*
QuicOperationDequeue(
    _In_ QUIC_OPERATION_QUEUE* OperQ
    )
{
    QUIC_OPERATION* Oper;
    CxPlatDispatchLockAcquire(&OperQ->Lock);
    if (CxPlatListIsEmpty(&OperQ->List)) {
        OperQ->ActivelyProcessing = FALSE;
        Oper = NULL;
    } else {
        OperQ->ActivelyProcessing = TRUE;
        Oper =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&OperQ->List), QUIC_OPERATION, Link);
#if DEBUG
        Oper->Link.Flink = NULL;
#endif
    }
    CxPlatDispatchLockRelease(&OperQ->Lock);

    if (Oper != NULL) {
        QuicPerfCounterDecrement(QUIC_PERF_COUNTER_CONN_OPER_QUEUE_DEPTH);
    }
    return Oper;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicOperationQueueClear(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_OPERATION_QUEUE* OperQ
    )
{
    CXPLAT_LIST_ENTRY OldList;
    CxPlatListInitializeHead(&OldList);

    CxPlatDispatchLockAcquire(&OperQ->Lock);
    OperQ->ActivelyProcessing = FALSE;
    CxPlatListMoveItems(&OperQ->List, &OldList);
    CxPlatDispatchLockRelease(&OperQ->Lock);

    int64_t OperationsDequeued = 0;

    while (!CxPlatListIsEmpty(&OldList)) {
        QUIC_OPERATION* Oper =
            CXPLAT_CONTAINING_RECORD(CxPlatListRemoveHead(&OldList), QUIC_OPERATION, Link);
        --OperationsDequeued;
#if DEBUG
        Oper->Link.Flink = NULL;
#endif
        if (Oper->FreeAfterProcess) {
            if (Oper->Type == QUIC_OPER_TYPE_API_CALL) {
                QUIC_API_CONTEXT* ApiCtx = Oper->API_CALL.Context;
                if (ApiCtx->Type == QUIC_API_TYPE_STRM_START) {
                    CXPLAT_DBG_ASSERT(ApiCtx->Completed == NULL);
                    QuicStreamIndicateStartComplete(
                        ApiCtx->STRM_START.Stream, QUIC_STATUS_ABORTED);
                    if (ApiCtx->STRM_START.Flags & QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL) {
                        QuicStreamShutdown(
                            ApiCtx->STRM_START.Stream,
                            QUIC_STREAM_SHUTDOWN_FLAG_ABORT | QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE,
                            0);
                    }
                }
            }
            QuicOperationFree(Worker, Oper);
        } else {
            CXPLAT_DBG_ASSERT(Oper->Type == QUIC_OPER_TYPE_API_CALL);
            if (Oper->Type == QUIC_OPER_TYPE_API_CALL) {
                QUIC_API_CONTEXT* ApiCtx = Oper->API_CALL.Context;
                if (ApiCtx->Status != NULL) {
                    *ApiCtx->Status = QUIC_STATUS_INVALID_STATE;
                    CxPlatEventSet(*ApiCtx->Completed);
                }
            }
        }
    }
    QuicPerfCounterAdd(QUIC_PERF_COUNTER_CONN_OPER_QUEUE_DEPTH, OperationsDequeued);
}
