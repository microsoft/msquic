/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the send logic

--*/

#include "main.h"


//
// Helper to set up a mock connection with real Partition and OperQ for testing
// the inner path of QuicSendQueueFlush and QuicSendStartDelayedAckTimer.
//
struct MockSendContextWithPartition {
    QUIC_CONNECTION Connection;
    QUIC_PACKET_SPACE PacketSpaces[QUIC_ENCRYPT_LEVEL_COUNT];
    QUIC_PARTITION DummyPartition;
    BOOLEAN PartitionCreated;

    MockSendContextWithPartition(bool IsServer = true) {
        CxPlatZeroMemory(&Connection, sizeof(Connection));
        CxPlatZeroMemory(PacketSpaces, sizeof(PacketSpaces));
        PartitionCreated = FALSE;

        ((QUIC_HANDLE*)&Connection)->Type =
            IsServer ? QUIC_HANDLE_TYPE_CONNECTION_SERVER : QUIC_HANDLE_TYPE_CONNECTION_CLIENT;
        Connection.RefCount = 1;

        //
        // If MsQuicLib.Partitions is NULL (lazy init hasn't run), create a
        // local dummy partition with initialized pools so that
        // QuicOperationAlloc / CxPlatPoolFree work correctly.
        //
        if (MsQuicLib.Partitions != NULL) {
            Connection.Partition = &MsQuicLib.Partitions[0];
        } else {
            CxPlatZeroMemory(&DummyPartition, sizeof(DummyPartition));
            CxPlatPoolInitialize(
                FALSE, sizeof(QUIC_SEND_REQUEST),
                QUIC_POOL_SEND_REQUEST, &DummyPartition.SendRequestPool);
            CxPlatPoolInitialize(
                FALSE, sizeof(QUIC_OPERATION),
                QUIC_POOL_OPER, &DummyPartition.OperPool);
            CxPlatPoolInitialize(
                FALSE, sizeof(QUIC_API_CONTEXT),
                QUIC_POOL_API_CTX, &DummyPartition.ApiContextPool);
            Connection.Partition = &DummyPartition;
            PartitionCreated = TRUE;
        }

        //
        // Initialize operation queue with ActivelyProcessing = TRUE
        // so QuicConnQueueOper does not signal a Worker.
        //
        QuicOperationQueueInitialize(&Connection.OperQ);
        Connection.OperQ.ActivelyProcessing = TRUE;

        CxPlatListInitializeHead(&Connection.Send.SendStreams);
        Connection.Send.FlushOperationPending = FALSE;

        //
        // All timers at UINT64_MAX so QuicConnTimerCancel is a no-op.
        //
        for (int i = 0; i < QUIC_CONN_TIMER_COUNT; i++) {
            Connection.ExpirationTimes[i] = UINT64_MAX;
        }
        Connection.EarliestExpirationTime = UINT64_MAX;

        for (int i = 0; i < QUIC_ENCRYPT_LEVEL_COUNT; i++) {
            PacketSpaces[i].Connection = &Connection;
            PacketSpaces[i].EncryptLevel = (QUIC_ENCRYPT_LEVEL)i;
        }
        Connection.Packets[QUIC_ENCRYPT_LEVEL_1_RTT] =
            &PacketSpaces[QUIC_ENCRYPT_LEVEL_1_RTT];

        Connection.Crypto.TlsState.WriteKey = QUIC_PACKET_KEY_1_RTT;
        Connection.Settings.ConnFlowControlWindow = 65536;
        Connection.Settings.MaxAckDelayMs = 25;

        Connection.State.Started = TRUE;
        Connection.State.Initialized = TRUE;
        Connection.Paths[0].IsActive = TRUE;
        Connection.Paths[0].EcnValidationState = ECN_VALIDATION_FAILED;
        Connection.Paths[0].Mtu = 1280;
        Connection.PathsCount = 1;
        CxPlatListInitializeHead(&Connection.DestCids);
#if DEBUG
        for (uint32_t i = 0; i < QUIC_CONN_REF_COUNT; i++) {
            CxPlatRefInitialize(&Connection.RefTypeBiasedCount[i]);
        }
#endif
    }

    ~MockSendContextWithPartition() {
        //
        // Drain any queued operations before cleanup.
        //
        QuicOperationQueueClear(&Connection.OperQ, Connection.Partition);
        QuicOperationQueueUninitialize(&Connection.OperQ);

        if (PartitionCreated) {
            CxPlatPoolUninitialize(&DummyPartition.SendRequestPool);
            CxPlatPoolUninitialize(&DummyPartition.OperPool);
            CxPlatPoolUninitialize(&DummyPartition.ApiContextPool);
        }
    }

    QUIC_SEND* Send() { return &Connection.Send; }

    void SetAckEliciting(QUIC_ENCRYPT_LEVEL Level, uint16_t Count) {
        if (Connection.Packets[Level] == nullptr) {
            Connection.Packets[Level] = &PacketSpaces[Level];
        }
        Connection.Packets[Level]->AckTracker.AckElicitingPacketsToAcknowledge = Count;
    }
};


//
// Test: QuicSendFlush with pacing-delayed result.
// Scenario: Enable pacing (PacingEnabled, GotFirstRttSample, SmoothedRtt >=
// QUIC_MIN_PACING_RTT), set BytesInFlight just below CongestionWindow so
// CanSend=TRUE but SendAllowance=0 (pacing chunk exhausted). SendFlags=PING
// (not a bypass flag). After CC block, SendFlags &= BYPASS_CC = 0. Since
// CanSend=TRUE, the pacing path (lines 1340-1347) is taken:
// QUIC_SEND_DELAYED_PACING. Timer is safely set because IDLE timer holds
// EarliestExpirationTime low.
// Assertions: Returns TRUE (DELAYED_PACING != INCOMPLETE), PING flag
// preserved, PACING timer set.
//
TEST(DeepTest_SendTest, FlushPacingDelayed)
{
    MockSendContextWithPartition Ctx;
    QUIC_SETTINGS_INTERNAL Settings = {};
    Settings.ConnFlowControlWindow = 65536;
    Settings.InitialWindowPackets = QUIC_INITIAL_WINDOW_PACKETS;
    Settings.PacingEnabled = TRUE;
    QuicSendInitialize(Ctx.Send(), &Settings);

    //
    // Also set PacingEnabled in the connection settings (CC reads from there).
    //
    Ctx.Connection.Settings.PacingEnabled = TRUE;

    QuicCongestionControlInitialize(&Ctx.Connection.CongestionControl, &Settings);

    //
    // Set up pacing conditions: BytesInFlight < CongestionWindow (CanSend=TRUE),
    // but pacing will return SendAllowance=0 because TimeSinceLastSend is near 0
    // and LastSendAllowance=0.
    //
    uint32_t CW = Ctx.Connection.CongestionControl.Cubic.CongestionWindow;
    ASSERT_GT(CW, 0u);
    Ctx.Connection.CongestionControl.Cubic.BytesInFlight = CW - 1;
    Ctx.Connection.CongestionControl.Cubic.LastSendAllowance = 0;

    //
    // Enable pacing by setting RTT sample.
    //
    Ctx.Connection.Paths[0].GotFirstRttSample = TRUE;
    Ctx.Connection.Paths[0].SmoothedRtt = 100000; // 100ms > QUIC_MIN_PACING_RTT(1000)

    //
    // Set LastFlushTimeValid so pacing calculation uses TimeSinceLastSend near 0.
    //
    Ctx.Connection.Send.LastFlushTimeValid = TRUE;
    Ctx.Connection.Send.LastFlushTime = CxPlatTimeUs64();

    uint8_t SourceCidBuf[sizeof(QUIC_CID_HASH_ENTRY) + 8] = {};
    QUIC_CID_HASH_ENTRY* SourceCid = (QUIC_CID_HASH_ENTRY*)SourceCidBuf;
    Ctx.Connection.SourceCids.Next = &SourceCid->Link;
    SourceCid->Link.Next = NULL;

    uint8_t DestCidBuf[sizeof(QUIC_CID_LIST_ENTRY) + 8] = {};
    QUIC_CID_LIST_ENTRY* DestCid = (QUIC_CID_LIST_ENTRY*)DestCidBuf;
    Ctx.Connection.Paths[0].Route.State = RouteResolved;
    Ctx.Connection.Paths[0].DestCid = DestCid;
    Ctx.Connection.Paths[0].IsPeerValidated = TRUE;
    Ctx.Connection.Paths[0].Allowance = UINT32_MAX;

    //
    // Set IDLE timer to 1 so EarliestExpirationTime stays at 1 when PACING
    // timer is set. This prevents QuicConnTimerSetEx from accessing Worker.
    //
    Ctx.Connection.ExpirationTimes[QUIC_CONN_TIMER_IDLE] = 1;
    Ctx.Connection.EarliestExpirationTime = 1;

    Ctx.Send()->SendFlags = QUIC_CONN_SEND_FLAG_PING;

    //
    // The follwing call fails with Code: 3221225477: EXCEPTION_ACCESS_VIOLATION
    //
    BOOLEAN Result = QuicSendFlush(Ctx.Send());

    //
    // QUIC_SEND_DELAYED_PACING != QUIC_SEND_INCOMPLETE, so returns TRUE.
    //
    ASSERT_TRUE(Result);

    //
    // PACING timer should have been set (no longer UINT64_MAX).
    //
    ASSERT_NE(Ctx.Connection.ExpirationTimes[QUIC_CONN_TIMER_PACING], UINT64_MAX);
}
