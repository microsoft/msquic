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
    QuicDispatchLockInitialize(&OperQ->Lock);
    QuicListInitializeHead(&OperQ->List);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicOperationQueueUninitialize(
    _In_ QUIC_OPERATION_QUEUE* OperQ
    )
{
    UNREFERENCED_PARAMETER(OperQ);
    QUIC_DBG_ASSERT(QuicListIsEmpty(&OperQ->List));
    QuicDispatchLockUninitialize(&OperQ->Lock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_OPERATION*
QuicOperationAlloc(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_OPERATION_TYPE Type
    )
{
    QUIC_OPERATION* Oper = (QUIC_OPERATION*)QuicPoolAlloc(&Worker->OperPool);
    if (Oper != NULL) {
#if DEBUG
        Oper->Link.Flink = NULL;
#endif
        Oper->Type = Type;
        Oper->FreeAfterProcess = TRUE;

        if (Oper->Type == QUIC_OPER_TYPE_API_CALL) {
            Oper->API_CALL.Context =
                (QUIC_API_CONTEXT*)QuicPoolAlloc(&Worker->ApiContextPool);
            if (Oper->API_CALL.Context == NULL) {
                QuicPoolFree(&Worker->OperPool, Oper);
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
    QUIC_DBG_ASSERT(Oper->Link.Flink == NULL);
#endif
    QUIC_DBG_ASSERT(Oper->FreeAfterProcess);
    if (Oper->Type == QUIC_OPER_TYPE_API_CALL) {
        QUIC_API_CONTEXT* ApiCtx = Oper->API_CALL.Context;
        if (ApiCtx->Type == QUIC_API_TYPE_CONN_START) {
            if (ApiCtx->CONN_START.ServerName != NULL) {
                QUIC_FREE(ApiCtx->CONN_START.ServerName);
            }
        } else if (ApiCtx->Type == QUIC_API_TYPE_CONN_SEND_RESUMPTION_TICKET) {
            if (ApiCtx->CONN_SEND_RESUMPTION_TICKET.ResumptionAppData != NULL) {
                QUIC_DBG_ASSERT(ApiCtx->CONN_SEND_RESUMPTION_TICKET.AppDataLength != 0);
                QUIC_FREE(ApiCtx->CONN_SEND_RESUMPTION_TICKET.ResumptionAppData);
            }
        } else if (ApiCtx->Type == QUIC_API_TYPE_STRM_START) {
            QUIC_DBG_ASSERT(ApiCtx->Completed == NULL);
            QuicStreamRelease(ApiCtx->STRM_START.Stream, QUIC_STREAM_REF_OPERATION);
        } else if (ApiCtx->Type == QUIC_API_TYPE_STRM_SHUTDOWN) {
            QuicStreamRelease(ApiCtx->STRM_SHUTDOWN.Stream, QUIC_STREAM_REF_OPERATION);
        } else if (ApiCtx->Type == QUIC_API_TYPE_STRM_SEND) {
            QuicStreamRelease(ApiCtx->STRM_SEND.Stream, QUIC_STREAM_REF_OPERATION);
        } else if (ApiCtx->Type == QUIC_API_TYPE_STRM_RECV_COMPLETE) {
            QuicStreamRelease(ApiCtx->STRM_RECV_COMPLETE.Stream, QUIC_STREAM_REF_OPERATION);
        } else if (ApiCtx->Type == QUIC_API_TYPE_STRM_RECV_SET_ENABLED) {
            QuicStreamRelease(ApiCtx->STRM_RECV_SET_ENABLED.Stream, QUIC_STREAM_REF_OPERATION);
        }
        QuicPoolFree(&Worker->ApiContextPool, ApiCtx);
    } else if (Oper->Type == QUIC_OPER_TYPE_FLUSH_STREAM_RECV) {
        QuicStreamRelease(Oper->FLUSH_STREAM_RECEIVE.Stream, QUIC_STREAM_REF_OPERATION);
    } else if (Oper->Type >= QUIC_OPER_TYPE_VERSION_NEGOTIATION) {
        if (Oper->STATELESS.Context != NULL) {
            QuicBindingReleaseStatelessOperation(Oper->STATELESS.Context, TRUE);
        }
    }
    QuicPoolFree(&Worker->OperPool, Oper);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicOperationEnqueue(
    _In_ QUIC_OPERATION_QUEUE* OperQ,
    _In_ QUIC_OPERATION* Oper
    )
{
    BOOLEAN StartProcessing;
    QuicDispatchLockAcquire(&OperQ->Lock);
#if DEBUG
    QUIC_DBG_ASSERT(Oper->Link.Flink == NULL);
#endif
    StartProcessing = QuicListIsEmpty(&OperQ->List) && !OperQ->ActivelyProcessing;
    QuicListInsertTail(&OperQ->List, &Oper->Link);
    QuicDispatchLockRelease(&OperQ->Lock);
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
    QuicDispatchLockAcquire(&OperQ->Lock);
#if DEBUG
    QUIC_DBG_ASSERT(Oper->Link.Flink == NULL);
#endif
    StartProcessing = QuicListIsEmpty(&OperQ->List) && !OperQ->ActivelyProcessing;
    QuicListInsertHead(&OperQ->List, &Oper->Link);
    QuicDispatchLockRelease(&OperQ->Lock);
    return StartProcessing;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_OPERATION*
QuicOperationDequeue(
    _In_ QUIC_OPERATION_QUEUE* OperQ
    )
{
    QUIC_OPERATION* Oper;
    QuicDispatchLockAcquire(&OperQ->Lock);
    if (QuicListIsEmpty(&OperQ->List)) {
        OperQ->ActivelyProcessing = FALSE;
        Oper = NULL;
    } else {
        OperQ->ActivelyProcessing = TRUE;
        Oper =
            QUIC_CONTAINING_RECORD(
                QuicListRemoveHead(&OperQ->List), QUIC_OPERATION, Link);
#if DEBUG
        Oper->Link.Flink = NULL;
#endif
    }
    QuicDispatchLockRelease(&OperQ->Lock);
    return Oper;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicOperationQueueClear(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_OPERATION_QUEUE* OperQ
    )
{
    QUIC_LIST_ENTRY OldList;
    QuicListInitializeHead(&OldList);

    QuicDispatchLockAcquire(&OperQ->Lock);
    OperQ->ActivelyProcessing = FALSE;
    QuicListMoveItems(&OperQ->List, &OldList);
    QuicDispatchLockRelease(&OperQ->Lock);

    while (!QuicListIsEmpty(&OldList)) {
        QUIC_OPERATION* Oper =
            QUIC_CONTAINING_RECORD(QuicListRemoveHead(&OldList), QUIC_OPERATION, Link);
#if DEBUG
        Oper->Link.Flink = NULL;
#endif
        if (Oper->FreeAfterProcess) {
            if (Oper->Type == QUIC_OPER_TYPE_API_CALL) {
                QUIC_API_CONTEXT* ApiCtx = Oper->API_CALL.Context;
                if (ApiCtx->Type == QUIC_API_TYPE_STRM_START) {
                    QUIC_DBG_ASSERT(ApiCtx->Completed == NULL);
                    QuicStreamIndicateStartComplete(
                        ApiCtx->STRM_START.Stream, QUIC_STATUS_ABORTED);
                }
            }
            QuicOperationFree(Worker, Oper);
        } else {
            QUIC_DBG_ASSERT(Oper->Type == QUIC_OPER_TYPE_API_CALL);
            if (Oper->Type == QUIC_OPER_TYPE_API_CALL) {
                QUIC_API_CONTEXT* ApiCtx = Oper->API_CALL.Context;
                if (ApiCtx->Status != NULL) {
                    *ApiCtx->Status = QUIC_STATUS_INVALID_STATE;
                    QuicEventSet(*ApiCtx->Completed);
                }
            }
        }
    }
}