# Semantic Index: CubicCongestionControlOnDataAcknowledged

## 1. Focal Function Overview

**Function**: `CubicCongestionControlOnDataAcknowledged`
**Location**: `src/core/cubic.c` lines 438-717
**Public Interface**: Called via function pointer `QuicCongestionControlOnDataAcknowledged` (inline wrapper at `src/core/congestion_control.h:305`)

### Summary
Processes ACK events for acknowledged data and adjusts CUBIC congestion window according to the CUBIC algorithm (RFC 8312). Handles slow start, congestion avoidance, HyStart++, and state transitions.

### Preconditions
- `Cc` must be valid QUIC_CONGESTION_CONTROL pointer with initialized Cubic state
- `AckEvent` must be valid with:
  - `TimeNow` set (microseconds)
  - `NumRetransmittableBytes` ≤ `Cubic->BytesInFlight`
  - `LargestAck`, `LargestSentPacketNumber` valid packet numbers
  - `SmoothedRtt` valid if used
  - `MinRtt`, `MinRttValid` properly set if HyStart enabled

### Postconditions
- `Cubic->BytesInFlight` decremented by `AckEvent->NumRetransmittableBytes`
- `Cubic->CongestionWindow` may grow (slow start or congestion avoidance)
- `Cubic->TimeOfLastAck` = `AckEvent->TimeNow`
- `Cubic->TimeOfLastAckValid` = TRUE
- Returns TRUE if connection became unblocked (can send data)
- May transition recovery state (`IsInRecovery` → FALSE)
- May update HyStart state and related fields

### Invariants
- `BytesInFlight` ≥ 0 (maintained by ASSERT at line 450)
- `CongestionWindow` ≤ 2 * `BytesInFlightMax` (enforced at lines 683-685)
- `CongestionWindow` ≥ `SlowStartThreshold` when in congestion avoidance
- If `IsInRecovery`, window growth is suppressed

### Error Contracts
- Asserts if `BytesInFlight < NumRetransmittableBytes` (CXPLAT_DBG_ASSERT line 450)
- No explicit error return; operates on valid state

### Resource/Ownership Model
- Does not allocate/free memory
- Modifies `Cubic` state in-place
- May emit trace events via `QuicTraceEvent` and `QuicTraceLogConnVerbose`
- May call `QuicConnIndicateEvent` if `NetStatsEventEnabled`

---

## 2. Call Graph

### Direct Callees (from OnDataAcknowledged)
1. **QuicCongestionControlGetConnection** (connection.h:817) - Gets Connection pointer from Cc
2. **CubicCongestionControlCanSend** (cubic.c:129) - Checks if can send
3. **QuicTraceEvent** (macro) - Logging (lines 460-463)
4. **CxPlatTimeDiff64** (platform macro) - Time difference calculation (lines 581, 592)
5. **CxPlatTimeAtOrBefore64** (platform macro) - Time comparison (line 585)
6. **QuicPathGetDatagramPayloadSize** (inline) - Get MTU (line 572)
7. **CubicCongestionControlUpdateBlockedState** (cubic.c:249) - Update blocked state (line 716)
8. **QuicTraceLogConnVerbose** (macro) - Verbose logging (line 703)
9. **QuicConnIndicateEvent** (function) - Event indication (line 713)

### Indirect Callees (via CubicCongestionControlUpdateBlockedState)
- **QuicConnLogOutFlowStats** - Log flow stats
- **QuicConnAddOutFlowBlockedReason** - Add blocked reason
- **QuicConnRemoveOutFlowBlockedReason** - Remove blocked reason  
- **CxPlatTimeUs64** - Get current time

### Callers (Public Interface)
- **QuicCongestionControlOnDataAcknowledged** (congestion_control.h:305) - inline wrapper
- Called from **loss_detection.c** in `QuicLossDetectionProcessAckFrame` when ACKs are processed

---

## 3. Control Flow Graph

### Main Path Structure
```
Entry (line 438)
│
├─ Initialize & Decrement BytesInFlight (lines 445-451)
│
├─ [IsInRecovery branch] (lines 453-468)
│  ├─ Check if LargestAck > RecoverySentPacketNumber (line 454)
│  │  ├─ TRUE: Exit recovery, set TimeOfCongAvoidStart, reset flags (lines 460-467)
│  │  └─ FALSE: continue in recovery
│  └─ goto Exit (line 468)
│
├─ [BytesAcked == 0 branch] (lines 469-471)
│  └─ goto Exit (line 470)
│
├─ HyStart++ Processing (lines 476-539) [if HyStartEnabled && state != DONE]
│  ├─ Update MinRtt samples (lines 477-519)
│  │  ├─ [AckCount < N_SAMPLING] (line 481): Update MinRttInCurrentRound (lines 482-486)
│  │  ├─ [State == NOT_STARTED] (line 487): Check for delay increase (lines 488-510)
│  │  │  └─ Transition to HYSTART_ACTIVE if delay threshold exceeded (lines 504-509)
│  │  └─ [State == ACTIVE] (line 511): Check if RTT decreased (lines 515-517)
│  │     └─ Resume slow start if RTT improved (line 516)
│  │
│  └─ Reset per-RTT round (lines 524-538)
│     ├─ Check if LargestAck >= HyStartRoundEnd (line 524)
│     └─ If ACTIVE: decrement rounds, possibly transition to DONE (lines 526-535)
│
├─ Slow Start Phase (lines 541-561) [if CongestionWindow < SlowStartThreshold]
│  ├─ Grow window: CongestionWindow += BytesAcked / CWndSlowStartGrowthDivisor (line 547)
│  ├─ Set BytesAcked = 0 (line 548)
│  └─ Check if exceeded threshold (line 549)
│     ├─ Set TimeOfCongAvoidStart (line 550)
│     ├─ Calculate overflow: BytesAcked = excess (line 558)
│     └─ Clamp to threshold (line 559)
│
├─ Congestion Avoidance Phase (lines 563-671) [if BytesAcked > 0]
│  ├─ Adjust TimeOfCongAvoidStart for idle gaps (lines 580-589)
│  ├─ Calculate TimeInCongAvoidUs (lines 591-592)
│  ├─ Calculate DeltaT for CUBIC formula (lines 610-618)
│  ├─ Compute CubicWindow using cubic function (lines 620-631)
│  ├─ Update AimdWindow (AIMD algorithm) (lines 648-657)
│  └─ Choose final window (lines 659-670)
│     ├─ If AimdWindow > CubicWindow: use AimdWindow (line 663)
│     └─ Else: constrain CubicWindow growth, use it (lines 668-669)
│
├─ Limit window based on BytesInFlightMax (lines 683-685)
│
└─ Exit: (lines 687-716)
   ├─ Update TimeOfLastAck (lines 689-690)
   ├─ Send network statistics event if enabled (lines 692-714)
   └─ Call UpdateBlockedState and return (line 716)
```

### Branch Conditions Summary
1. **IsInRecovery** (line 453) - Skip window growth if in recovery
2. **LargestAck > RecoverySentPacketNumber** (line 454) - Exit recovery
3. **BytesAcked == 0** (line 469) - Skip growth if nothing acked
4. **HyStartEnabled && state != DONE** (line 476) - HyStart processing
5. **MinRttValid** (line 477) - HyStart RTT update
6. **HyStartAckCount < N_SAMPLING** (line 481) - Still sampling
7. **HyStartState == NOT_STARTED** (line 487) - Check for delay increase
8. **MinRtt increase >= Eta** (line 499) - Trigger HyStart ACTIVE
9. **HyStartState == ACTIVE** (line 511) - Check for RTT decrease
10. **MinRtt decreased** (line 515) - Resume slow start
11. **LargestAck >= HyStartRoundEnd** (line 524) - RTT round boundary
12. **ConservativeSlowStartRounds == 0** (line 527) - Exit conservative SS
13. **CongestionWindow < SlowStartThreshold** (line 541) - Slow start
14. **CongestionWindow >= SlowStartThreshold** (line 549) - Transition to CA
15. **BytesAcked > 0** (line 563) - Congestion avoidance
16. **TimeOfLastAckValid** (line 580) - Idle gap adjustment
17. **TimeSinceLastAck > idle threshold** (line 582) - Freeze window growth
18. **CubicWindow < 0** (line 625) - Overflow protection
19. **AimdWindow < WindowPrior** (line 649) - Slower AIMD growth
20. **AimdWindow > CubicWindow** (line 659) - Reno-friendly region
21. **CongestionWindow > 2 * BytesInFlightMax** (line 683) - Limit growth
22. **NetStatsEventEnabled** (line 692) - Emit statistics

---

## 4. Data Flow Graph

### Key Data Dependencies

**Inputs (from AckEvent)**
- `TimeNow` → Used in recovery exit (line 466), idle gap calc (line 581), DeltaT (line 614)
- `NumRetransmittableBytes` → Decrements BytesInFlight (line 451), drives window growth (line 547, 650, 652)
- `LargestAck` → Recovery exit check (line 454), HyStart round boundary (line 524)
- `SmoothedRtt` → CUBIC DeltaT calculation (line 614), idle timeout (line 583)
- `MinRtt` → HyStart delay detection (lines 483, 499)
- `MinRttValid` → Gates HyStart RTT processing (line 477)

**State Reads**
- `Cubic->IsInRecovery` → Skip growth if TRUE (line 453)
- `Cubic->BytesInFlight` → Decremented (line 451), compared for send allowance
- `Cubic->CongestionWindow` → Read for growth decisions (lines 541, 549, 683), written with new value
- `Cubic->SlowStartThreshold` → Phase decision (line 541)
- `Cubic->HyStartState` → Determines HyStart logic path (lines 476, 487, 511, 526)
- `Cubic->TimeOfLastAck` → Idle gap calculation (line 581)
- `Cubic->TimeOfCongAvoidStart` → CUBIC time calculation (lines 584, 592)
- `Cubic->WindowMax`, `WindowPrior`, `KCubic` → CUBIC formula inputs
- `Connection->Settings.HyStartEnabled` → Gates HyStart processing (line 476)
- `Connection->Paths[0].SmoothedRtt` → Used in idle timeout, DeltaT
- `Connection->Send.NextPacketNumber` → HyStart round end update (line 525)

**State Writes**
- `Cubic->BytesInFlight` ← Decremented by NumRetransmittableBytes (line 451)
- `Cubic->CongestionWindow` ← Grown in slow start (line 547) or congestion avoidance (lines 663, 669)
- `Cubic->IsInRecovery` ← FALSE when exiting recovery (line 464)
- `Cubic->IsInPersistentCongestion` ← FALSE when exiting recovery (line 465)
- `Cubic->TimeOfCongAvoidStart` ← Set on SS→CA transition (lines 466, 550, 532), adjusted for idle (line 584)
- `Cubic->TimeOfLastAck` ← AckEvent->TimeNow (line 689)
- `Cubic->TimeOfLastAckValid` ← TRUE (line 690)
- `Cubic->HyStartState` ← Transitions via CubicCongestionHyStartChangeState
- `Cubic->MinRttInCurrentRound` ← Updated with new samples (lines 483, 509)
- `Cubic->HyStartAckCount` ← Incremented (line 486)
- `Cubic->HyStartRoundEnd` ← Next packet number at round boundary (line 525)
- `Cubic->SlowStartThreshold` ← Set when exiting conservative SS (line 531)
- `Cubic->AimdWindow` ← Updated in CA, set on CSS exit (lines 533, 655)
- `Cubic->AimdAccumulator` ← Accumulates acked bytes (lines 650, 652), decremented (line 656)
- `Cubic->CWndSlowStartGrowthDivisor` ← Set via HyStart state change
- `Cubic->ConservativeSlowStartRounds` ← Decremented in ACTIVE state (line 527)
- `Cubic->CssBaselineMinRtt` ← Baseline for CSS (line 509)

**Output**
- Return value: BOOLEAN from CubicCongestionControlUpdateBlockedState (line 716)

### Tainted Inputs / Validation
- **AckEvent fields** are assumed validated by caller (loss_detection.c)
- **BytesInFlight >= NumRetransmittableBytes** enforced by ASSERT (line 450)
- No explicit range validation on time values (assumed monotonic)
- DeltaT clamped to 2500000ms to prevent overflow (lines 616-618)
- CubicWindow overflow check (line 625) - if negative, clamp to 2*BytesInFlightMax

---

## 5. Function Annotations

### CubicCongestionControlCanSend (cubic.c:129)
**Summary**: Checks if more data can be sent based on congestion window
**Preconditions**: Valid Cc pointer
**Postconditions**: Returns TRUE if BytesInFlight < CongestionWindow OR Exemptions > 0
**Invariants**: Read-only function
**Side effects**: None

### CubicCongestionControlUpdateBlockedState (cubic.c:249)
**Summary**: Updates flow-blocked state and logs, checks if became unblocked
**Preconditions**: Valid Cc, PreviousCanSendState is previous CubicCongestionControlCanSend() result
**Postconditions**: 
  - Flow blocked reasons updated in Connection
  - Logs emitted
  - Returns TRUE if transitioned from blocked → unblocked
**Invariants**: Must be called after state changes affecting CanSend
**Side effects**: 
  - Adds/removes QUIC_FLOW_BLOCKED_CONGESTION_CONTROL reason
  - Updates Connection->Send.LastFlushTime if unblocked
  - Emits QuicConnLogOutFlowStats

### CubicCongestionHyStartChangeState (cubic.c:84)
**Summary**: Transitions HyStart state, updates CWndSlowStartGrowthDivisor
**Preconditions**: Valid Cc, valid NewHyStartState value, HyStartEnabled checked by caller
**Postconditions**: 
  - Cubic->HyStartState = NewHyStartState
  - CWndSlowStartGrowthDivisor set (1 for DONE/NOT_STARTED, unchanged for ACTIVE)
  - Trace event emitted if state changed
**Invariants**: State must be valid enum value
**Side effects**: Emits QuicTraceEvent if state changed

### CubicCongestionHyStartResetPerRttRound (cubic.c:118)
**Summary**: Resets per-RTT round HyStart counters
**Preconditions**: Valid Cubic pointer
**Postconditions**: 
  - HyStartAckCount = 0
  - MinRttInLastRound = MinRttInCurrentRound
  - MinRttInCurrentRound = UINT64_MAX
**Invariants**: Called at RTT round boundaries
**Side effects**: None

---

## 6. Path Enumeration for CubicCongestionControlOnDataAcknowledged

### Test Path Definitions

#### Path 1: IsInRecovery + LargestAck > RecoverySentPacketNumber (Exit Recovery)
**Conditions**:
1. Cubic->IsInRecovery == TRUE (line 453)
2. AckEvent->LargestAck > Cubic->RecoverySentPacketNumber (line 454)

**Outcome**: 
- Exit recovery: IsInRecovery = FALSE, IsInPersistentCongestion = FALSE
- TimeOfCongAvoidStart = TimeNow
- Trace event emitted
- goto Exit (no window growth)

**Lines**: [445,446,447,448,450,451,453,454,460,461,462,463,464,465,466,467,468,687,689,690,692,716]

#### Path 2: IsInRecovery + LargestAck ≤ RecoverySentPacketNumber (Stay in Recovery)
**Conditions**:
1. Cubic->IsInRecovery == TRUE (line 453)
2. AckEvent->LargestAck ≤ Cubic->RecoverySentPacketNumber (line 454)

**Outcome**: 
- Remain in recovery
- goto Exit (no window growth)

**Lines**: [445,446,447,448,450,451,453,454,468,687,689,690,692,716]

#### Path 3: Not in Recovery + BytesAcked == 0
**Conditions**:
1. Cubic->IsInRecovery == FALSE (line 453)
2. BytesAcked == 0 (line 469)

**Outcome**: 
- No window growth (no bytes to acknowledge)
- goto Exit

**Lines**: [445,446,447,448,450,451,453,469,470,687,689,690,692,716]

#### Path 4: HyStart Disabled (No HyStart Processing) + Slow Start
**Conditions**:
1. IsInRecovery == FALSE
2. BytesAcked > 0
3. Connection->Settings.HyStartEnabled == FALSE (line 476)
4. CongestionWindow < SlowStartThreshold (line 541)
5. After growth: CongestionWindow < SlowStartThreshold (line 549)

**Outcome**:
- Skip HyStart block (lines 476-539)
- Grow window in slow start: CongestionWindow += BytesAcked / CWndSlowStartGrowthDivisor
- BytesAcked = 0, no congestion avoidance
- Apply BytesInFlightMax limit

**Lines**: [445,446,447,448,450,451,453,469,476,541,547,548,549,683,687,689,690,692,716]

#### Path 5: HyStart Disabled + Slow Start → Congestion Avoidance Transition
**Conditions**:
1. IsInRecovery == FALSE
2. BytesAcked > 0
3. HyStartEnabled == FALSE
4. CongestionWindow < SlowStartThreshold (line 541)
5. After growth: CongestionWindow >= SlowStartThreshold (line 549)

**Outcome**:
- Grow in slow start
- Detect threshold exceeded
- Set TimeOfCongAvoidStart
- Calculate overflow BytesAcked
- Clamp CongestionWindow to SlowStartThreshold
- Enter congestion avoidance with remaining BytesAcked

**Lines**: [445,446,447,448,450,451,453,469,476,541,547,548,549,550,558,559,563,569,571,572,580,591,592,610,611,612,613,614,615,616,620,621,622,623,625,648,649,650,652,654,655,656,659,663,683,687,689,690,692,716]

#### Path 6: HyStart Enabled + State == DONE + Slow Start
**Conditions**:
1. IsInRecovery == FALSE
2. BytesAcked > 0
3. HyStartEnabled == TRUE
4. HyStartState == HYSTART_DONE (line 476 condition fails)
5. CongestionWindow < SlowStartThreshold (line 541)
6. After growth: CongestionWindow < SlowStartThreshold

**Outcome**:
- Skip HyStart processing (state is DONE)
- Grow window in slow start normally

**Lines**: [445,446,447,448,450,451,453,469,476,541,547,548,549,683,687,689,690,692,716]

#### Path 7: HyStart NOT_STARTED + MinRttValid + AckCount < N_SAMPLING
**Conditions**:
1. HyStartEnabled == TRUE
2. HyStartState != HYSTART_DONE
3. MinRttValid == TRUE (line 477)
4. HyStartAckCount < QUIC_HYSTART_DEFAULT_N_SAMPLING (line 481)
5. Followed by slow start or CA

**Outcome**:
- Update MinRttInCurrentRound = min(current, MinRtt)
- Increment HyStartAckCount
- Continue to window growth

**Lines**: [445,446,447,448,450,451,453,469,476,477,481,482,483,484,485,486,(plus window growth paths)]

#### Path 8: HyStart NOT_STARTED + Detect Delay Increase → Transition to ACTIVE
**Conditions**:
1. HyStartEnabled == TRUE
2. HyStartState == HYSTART_NOT_STARTED
3. MinRttValid == TRUE
4. HyStartAckCount >= N_SAMPLING (line 481 fails, line 487 true)
5. MinRttInLastRound != UINT64_MAX && MinRttInCurrentRound != UINT64_MAX (line 497)
6. MinRttInCurrentRound >= MinRttInLastRound + Eta (line 499)
7. LargestAck < HyStartRoundEnd (line 524 fails)

**Outcome**:
- Transition to HYSTART_ACTIVE via CubicCongestionHyStartChangeState
- Set CWndSlowStartGrowthDivisor = 4 (CONSERVATIVE_SLOW_START_DEFAULT_GROWTH_DIVISOR)
- Set ConservativeSlowStartRounds = 5
- Set CssBaselineMinRtt
- Continue to slow start with modified growth divisor

**Lines**: [445,446,447,448,450,451,453,469,476,477,481,487,488,489,490,491,492,493,497,498,499,504,505,506,507,508,509,524,541,547,548,549,683,687,689,690,692,716]

#### Path 9: HyStart ACTIVE + RTT Decreased → Resume SlowStart (NOT_STARTED)
**Conditions**:
1. HyStartEnabled == TRUE
2. HyStartState == HYSTART_ACTIVE
3. MinRttValid == TRUE
4. HyStartAckCount >= N_SAMPLING (line 481 fails)
5. HyStartState != NOT_STARTED (line 487 fails, line 511 true)
6. MinRttInCurrentRound < CssBaselineMinRtt (line 515)

**Outcome**:
- Transition back to HYSTART_NOT_STARTED
- CWndSlowStartGrowthDivisor reset to 1
- Resume normal slow start growth

**Lines**: [445,446,447,448,450,451,453,469,476,477,481,487,511,515,516,524,541,547,548,549,683,687,689,690,692,716]

#### Path 10: HyStart ACTIVE + RTT Round Boundary + Rounds Remaining
**Conditions**:
1. HyStartEnabled == TRUE
2. HyStartState == HYSTART_ACTIVE
3. LargestAck >= HyStartRoundEnd (line 524)
4. ConservativeSlowStartRounds > 1 after decrement (line 527)

**Outcome**:
- Decrement ConservativeSlowStartRounds
- Update HyStartRoundEnd = NextPacketNumber
- Reset per-RTT round counters
- Continue conservative slow start

**Lines**: [445,446,447,448,450,451,453,469,476,477,524,525,526,527,537,541,547,548,549,683,687,689,690,692,716]

#### Path 11: HyStart ACTIVE + RTT Round Boundary + Exit to Congestion Avoidance
**Conditions**:
1. HyStartEnabled == TRUE
2. HyStartState == HYSTART_ACTIVE
3. LargestAck >= HyStartRoundEnd (line 524)
4. ConservativeSlowStartRounds == 1 (becomes 0 after decrement, line 527)

**Outcome**:
- Transition to HYSTART_DONE
- SlowStartThreshold = CongestionWindow
- TimeOfCongAvoidStart = TimeNow
- AimdWindow = CongestionWindow
- Enter congestion avoidance

**Lines**: [445,446,447,448,450,451,453,469,476,477,524,525,526,527,531,532,533,534,537,541,563,569,571,572,580,591,592,610,611,612,613,614,615,616,620,621,622,623,625,648,649,650,652,654,655,656,659,683,687,689,690,692,716]

#### Path 12: Congestion Avoidance + TimeOfLastAckValid == FALSE (No Idle Adjustment)
**Conditions**:
1. Not in recovery, BytesAcked > 0
2. CongestionWindow >= SlowStartThreshold (line 541 fails, line 563)
3. TimeOfLastAckValid == FALSE (line 580)

**Outcome**:
- Skip idle gap adjustment
- Calculate CUBIC and AIMD windows
- Grow congestion window

**Lines**: [445,446,447,448,450,451,453,469,476,541,563,569,571,572,580,591,592,610,611,612,613,614,615,616,620,621,622,623,625,648,649,650,652,654,655,656,659,683,687,689,690,692,716]

#### Path 13: Congestion Avoidance + Idle Gap Detected (Freeze Growth)
**Conditions**:
1. CongestionWindow >= SlowStartThreshold
2. TimeOfLastAckValid == TRUE (line 580)
3. TimeSinceLastAck > MS_TO_US(SendIdleTimeoutMs) (line 582)
4. TimeSinceLastAck > SmoothedRtt + 4*RttVariance (line 583)

**Outcome**:
- Adjust TimeOfCongAvoidStart forward by TimeSinceLastAck
- Effectively freezes window growth during idle period
- Continue CUBIC/AIMD calculation with adjusted time

**Lines**: [445,446,447,448,450,451,453,469,476,541,563,569,571,572,580,581,582,583,584,585,586,587,591,592,610,611,612,613,614,615,616,620,621,622,623,625,648,649,650,652,654,655,656,659,683,687,689,690,692,716]

#### Path 14: Congestion Avoidance + DeltaT Overflow Protection
**Conditions**:
1. CongestionWindow >= SlowStartThreshold
2. TimeInCongAvoidUs large enough that DeltaT > 2500000ms (line 616)

**Outcome**:
- Clamp DeltaT to 2500000ms
- Prevents overflow in cubic calculation
- Continue with clamped value

**Lines**: [445,446,447,448,450,451,453,469,476,541,563,569,571,572,580,591,592,610,611,612,613,614,615,616,617,620,621,622,623,625,648,649,650,652,654,655,656,659,683,687,689,690,692,716]

#### Path 15: Congestion Avoidance + CubicWindow Overflow (Negative)
**Conditions**:
1. CongestionWindow >= SlowStartThreshold
2. Cubic calculation overflows, CubicWindow < 0 (line 625)

**Outcome**:
- Set CubicWindow = 2 * BytesInFlightMax
- Prevents using corrupted value
- Continue with safe limit

**Lines**: [445,446,447,448,450,451,453,469,476,541,563,569,571,572,580,591,592,610,611,612,613,614,615,616,620,621,622,623,625,630,648,649,650,652,654,655,656,659,683,687,689,690,692,716]

#### Path 16: Congestion Avoidance + AimdWindow < WindowPrior (Slower AIMD Growth)
**Conditions**:
1. CongestionWindow >= SlowStartThreshold
2. AimdWindow < WindowPrior (line 649)
3. AimdAccumulator + BytesAcked/2 > AimdWindow (line 654)

**Outcome**:
- Accumulate BytesAcked/2 (half rate, per RFC 8312)
- Grow AimdWindow by DatagramPayloadLength when threshold reached
- Provides smoother convergence

**Lines**: [445,446,447,448,450,451,453,469,476,541,563,569,571,572,580,591,592,610,611,612,613,614,615,616,620,621,622,623,625,648,649,650,654,655,656,659,683,687,689,690,692,716]

#### Path 17: Congestion Avoidance + AimdWindow >= WindowPrior (Normal AIMD Growth)
**Conditions**:
1. CongestionWindow >= SlowStartThreshold
2. AimdWindow >= WindowPrior (line 649 fails, line 651)
3. AimdAccumulator + BytesAcked > AimdWindow (line 654)

**Outcome**:
- Accumulate full BytesAcked (1 MSS/RTT growth)
- Grow AimdWindow by DatagramPayloadLength when threshold reached
- Matches Reno aggressiveness per RFC 8312

**Lines**: [445,446,447,448,450,451,453,469,476,541,563,569,571,572,580,591,592,610,611,612,613,614,615,616,620,621,622,623,625,648,649,651,652,654,655,656,659,683,687,689,690,692,716]

#### Path 18: Congestion Avoidance + Reno-Friendly Region (Use AIMD Window)
**Conditions**:
1. CongestionWindow >= SlowStartThreshold
2. AimdWindow > CubicWindow (line 659)

**Outcome**:
- Use AimdWindow as CongestionWindow
- Reno-friendly region where AIMD is more aggressive than CUBIC
- Per RFC 8312 TCP-friendliness requirement

**Lines**: [445,446,447,448,450,451,453,469,476,541,563,569,571,572,580,591,592,610,611,612,613,614,615,616,620,621,622,623,625,648,649,654,659,663,683,687,689,690,692,716]

#### Path 19: Congestion Avoidance + Concave/Convex Region (Use Constrained CUBIC)
**Conditions**:
1. CongestionWindow >= SlowStartThreshold
2. AimdWindow ≤ CubicWindow (line 659 fails)
3. CubicWindow constrained to [CongestionWindow, CongestionWindow*1.5]

**Outcome**:
- Calculate TargetWindow = max(CongestionWindow, min(CubicWindow, CongestionWindow*1.5))
- Grow CongestionWindow proportionally toward TargetWindow
- Prevents excessive growth per RTT

**Lines**: [445,446,447,448,450,451,453,469,476,541,563,569,571,572,580,591,592,610,611,612,613,614,615,616,620,621,622,623,625,648,649,654,659,668,669,683,687,689,690,692,716]

#### Path 20: Window Limited by BytesInFlightMax
**Conditions**:
1. After growth: CongestionWindow > 2 * BytesInFlightMax (line 683)

**Outcome**:
- Clamp CongestionWindow = 2 * BytesInFlightMax
- Prevents window from growing when not actually using capacity
- App-limited or flow-control limited scenario

**Lines**: [445,446,447,448,450,451,453,469,476,541,(growth),683,684,687,689,690,692,716]

#### Path 21: Network Statistics Event Enabled
**Conditions**:
1. Connection->Settings.NetStatsEventEnabled == TRUE (line 692)

**Outcome**:
- Populate QUIC_CONNECTION_EVENT with network statistics
- Call QuicTraceLogConnVerbose with detailed stats
- Call QuicConnIndicateEvent to emit event to application

**Lines**: [687,689,690,692,693,694,695,696,697,698,699,700,701,702,703,704,705,706,707,708,709,710,711,712,713,716]

#### Path 22: Network Statistics Event Disabled
**Conditions**:
1. Connection->Settings.NetStatsEventEnabled == FALSE (line 692)

**Outcome**:
- Skip event emission
- Proceed directly to UpdateBlockedState

**Lines**: [687,689,690,692,716]

---

## 7. Security-Relevant Observations

### Memory Safety
- **Integer overflow protection**: DeltaT clamped (lines 616-618), CubicWindow overflow check (line 625)
- **ASSERT on BytesInFlight underflow**: Line 450 catches accounting errors
- **No dynamic allocation**: All operations on existing state, no heap usage

### Input Validation
- **AckEvent validation**: Assumed done by caller (loss_detection.c)
- **Packet number validation**: Comparison logic (lines 454, 524) assumes valid packet numbers
- **Time monotonicity**: No explicit check, assumes platform provides monotonic time

### Race Conditions / Concurrency
- **Single-threaded assumption**: No locking in function, relies on QUIC connection execution model
- **State consistency**: All state updates are in-order within function
- **Callback reentrancy**: QuicConnIndicateEvent (line 713) could theoretically re-enter QUIC stack

### Resource Exhaustion
- **Window growth limits**: BytesInFlightMax limit (line 683) prevents unbounded growth
- **Idle timeout protection**: Lines 582-587 prevent growth during idle periods
- **Conservative growth**: HyStart++ (lines 476-539) prevents premature slow start exit

### Potential Vulnerabilities
1. **Malicious ACKs**: If caller doesn't validate LargestAck, could manipulate recovery state (line 454)
2. **Time manipulation**: If TimeNow is attacker-controlled, could affect idle detection (line 581) and CUBIC calculations
3. **Overflow in accumulator**: AimdAccumulator (lines 650, 652) could overflow with extreme values, but clamped by comparison at line 654
4. **Bandwidth amplification**: Without proper validation, could ACK more bytes than sent, leading to incorrect BytesInFlight

---

## 8. Dependencies and Constants

### External Dependencies
- **Platform abstractions**: CxPlatTimeDiff64, CxPlatTimeAtOrBefore64, CxPlatTimeUs64, CxPlatZeroMemory
- **Logging**: QuicTraceEvent, QuicTraceLogConnVerbose
- **Connection functions**: QuicCongestionControlGetConnection, QuicPathGetDatagramPayloadSize, QuicConnLogOutFlowStats, QuicConnIndicateEvent, QuicSendBufferConnectionAdjust, QuicConnAddOutFlowBlockedReason, QuicConnRemoveOutFlowBlockedReason
- **Inline wrappers**: QuicCongestionControlCanSend (from congestion_control.h)

### Constants (from quicdef.h)
- `QUIC_HYSTART_DEFAULT_N_SAMPLING` = 8
- `QUIC_HYSTART_DEFAULT_MIN_ETA` = 4000 microseconds
- `QUIC_HYSTART_DEFAULT_MAX_ETA` = 16000 microseconds
- `QUIC_CONSERVATIVE_SLOW_START_DEFAULT_ROUNDS` = 5
- `QUIC_CONSERVATIVE_SLOW_START_DEFAULT_GROWTH_DIVISOR` = 4
- `QUIC_MIN_PACING_RTT` (referenced but value not in viewed files)
- `TEN_TIMES_BETA_CUBIC` = 7 (BETA = 0.7)
- `TEN_TIMES_C_CUBIC` = 4 (C = 0.4)
- `QUIC_PERSISTENT_CONGESTION_WINDOW_PACKETS` (from other functions)

### Macros
- `MS_TO_US(ms)` - milliseconds to microseconds
- `US_TO_MS(us)` - microseconds to milliseconds
- `S_TO_MS(s)` - seconds to milliseconds
- `CXPLAT_MIN(a, b)` - minimum
- `CXPLAT_MAX(a, b)` - maximum
- `CXPLAT_DBG_ASSERT(expr)` - debug assertion
- `CXPLAT_CONTAINING_RECORD(ptr, type, field)` - container_of macro

---

## 9. Test Coverage Analysis (Existing Tests)

### Existing Test Coverage from CubicTest.cpp

**Covered Scenarios**:
1. **Initialization** (Tests 1-3): Basic init, boundaries, re-init
2. **CanSend** (Test 4): Available window, blocked, exemptions
3. **SetExemption** (Test 5): Setting exemption counts
4. **GetSendAllowance** (Tests 6-7): Blocked, available, pacing scenarios
5. **Getters** (Test 8): GetExemptions, GetBytesInFlightMax, GetCongestionWindow
6. **Reset** (Test 9): Partial and full reset
7. **OnDataSent** (Test 10): BytesInFlight increment, exemption decrement
8. **OnDataInvalidated** (Test 11): BytesInFlight decrement
9. **OnDataAcknowledged - Basic** (Test 12): Simple ACK with window growth
10. **OnDataLost** (Test 13): Window reduction on loss
11. **OnEcn** (Test 14): ECN signal handling
12. **GetNetworkStatistics** (Test 15): Stats retrieval
13. **Miscellaneous** (Test 16): API completeness
14. **HyStart States** (Test 17): Basic state transition testing

**Gaps Identified** (Paths NOT Covered):
1. ❌ **Recovery exit path** (Path 1): IsInRecovery with LargestAck > RecoverySentPacketNumber
2. ❌ **Recovery continuation** (Path 2): IsInRecovery with LargestAck ≤ RecoverySentPacketNumber
3. ❌ **BytesAcked == 0 path** (Path 3): No retransmittable bytes acked
4. ✅ **HyStart disabled slow start** (Path 4): Covered by Test 12 implicitly (HyStart not enabled in existing tests)
5. ❌ **Slow start → CA transition** (Path 5): Window growth crossing threshold
6. ❌ **HyStart DONE + slow start** (Path 6): State DONE but still in slow start phase
7. ❌ **HyStart sampling** (Path 7): AckCount < N_SAMPLING, updating MinRtt
8. ❌ **HyStart delay increase detection** (Path 8): Transition NOT_STARTED → ACTIVE
9. ❌ **HyStart RTT decrease** (Path 9): ACTIVE → NOT_STARTED on RTT improvement
10. ❌ **HyStart CSS rounds remaining** (Path 10): Conservative slow start continuation
11. ❌ **HyStart CSS exit** (Path 11): Conservative slow start → CA transition
12. ❌ **CA without idle adjustment** (Path 12): TimeOfLastAckValid == FALSE
13. ❌ **CA with idle gap** (Path 13): Idle timeout triggers TimeOfCongAvoidStart adjustment
14. ❌ **DeltaT overflow** (Path 14): Very large TimeInCongAvoidUs
15. ❌ **CubicWindow overflow** (Path 15): Cubic calculation overflows to negative
16. ❌ **AIMD slow growth** (Path 16): AimdWindow < WindowPrior
17. ❌ **AIMD normal growth** (Path 17): AimdWindow >= WindowPrior
18. ❌ **Reno-friendly region** (Path 18): AimdWindow > CubicWindow
19. ❌ **CUBIC concave/convex** (Path 19): Constrained CUBIC growth
20. ❌ **BytesInFlightMax limiting** (Path 20): Window clamped by actual usage
21. ✅ **NetStats event enabled** (Path 21): Test 12 may trigger this
22. ✅ **NetStats event disabled** (Path 22): Most tests have this disabled

### Coverage Summary
- **Function entry/exit**: Covered ✅
- **Basic ACK processing**: Covered ✅ (Test 12)
- **Recovery paths**: **NOT covered** ❌
- **Slow start growth**: Partially covered ✅
- **SS → CA transition**: **NOT covered** ❌
- **HyStart++ algorithm**: **NOT covered** ❌ (Test 17 only checks states, not full algorithm)
- **Congestion avoidance**: Partially covered via Test 12, but specific CA paths **NOT covered** ❌
- **Idle gap handling**: **NOT covered** ❌
- **Overflow protections**: **NOT covered** ❌
- **AIMD vs CUBIC selection**: **NOT covered** ❌
- **Window growth limiting**: **NOT covered** ❌

---

## 10. Recommendations for New Tests

### High Priority (Core Algorithm Coverage)
1. **Recovery exit and continuation** (Paths 1, 2)
2. **Slow start to CA transition** (Path 5)
3. **HyStart++ full algorithm** (Paths 7-11)
4. **AIMD vs CUBIC window selection** (Paths 16-19)
5. **Overflow protections** (Paths 14, 15)
6. **BytesInFlightMax limiting** (Path 20)

### Medium Priority (Edge Cases)
7. **BytesAcked == 0 path** (Path 3)
8. **Idle gap adjustment** (Path 13)
9. **Multiple RTT rounds in CA** (Multiple ACKs with time progression)

### Low Priority (Already Partially Covered)
10. **HyStart disabled paths** (Path 4, 6) - already implicitly tested
11. **NetStats events** - already covered

### Security/Robustness Tests
12. **Integer overflow scenarios** - extreme values for time, window sizes
13. **Underflow protection** - verify ASSERT on BytesInFlight < BytesAcked
14. **Rapid state transitions** - recovery → CA → loss → recovery
15. **Concurrent slow start and HyStart** - verify correct divisor application

---

## 11. Index Persistence Format

This markdown document serves as the human-readable semantic index. For machine-readable format, a companion JSON file should be generated with:
- Function signatures
- Line number mappings for each path
- Dependency graph in adjacency list format
- State variable definitions
- Constants and macros

**File Location**: `.deeptest/semantic_index/CubicCongestionControlOnDataAcknowledged_semantic_index.json`

---

*Semantic Index Version: 1.0*
*Generated: 2025-12-17*
*Focal Function: CubicCongestionControlOnDataAcknowledged (src/core/cubic.c:438-717)*
