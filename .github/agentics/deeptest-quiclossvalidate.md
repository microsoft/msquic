<!-- This prompt will be imported in the agentic workflow .github/workflows/deeptest-quiclossvalidate.md at runtime. -->
<!-- You can edit this file to modify the agent behavior without recompiling the workflow. -->

# DeepTest: Generate Tests for QuicLossValidate

This workflow invokes the Copilot CLI with the DeepTest custom agent to generate comprehensive tests for the `QuicLossValidate` function.

## Target Function

- **File**: `src/core/loss_detection.c`
- **Function**: `QuicLossValidate`
- **Lines**: 93-115 (DEBUG-only validation function)

### Function Signature
```c
void QuicLossValidate(_In_ QUIC_LOSS_DETECTION* LossDetection)
```

### Function Behavior
1. Iterates through `SentPackets` linked list counting `AckElicitingPackets`
2. Asserts that no packet is marked as `Freed`
3. Asserts that `SentPacketsTail` points to the end of the list
4. Asserts that `PacketsInFlight` matches the count of ack-eliciting packets
5. Iterates through `LostPackets` linked list
6. Asserts that no lost packet is marked as `Freed`
7. Asserts that `LostPacketsTail` points to the end of the list

## Test Scenarios to Cover

- Empty sent packets list
- Empty lost packets list
- Single packet in sent list (ack-eliciting and non-ack-eliciting)
- Multiple packets in sent list with mixed ack-eliciting flags
- Single/multiple packets in lost list
- Both sent and lost lists populated
- Edge cases for PacketsInFlight count validation

## Safe Outputs

When successfully complete:
- If tests were generated: Use `create-pull-request` with the generated test code
- **If DeepTest agent is unavailable or failed**: Call the `noop` safe output explaining the failure
