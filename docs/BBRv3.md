# BBRv3 preview

Select `QUIC_CONGESTION_CONTROL_ALGORITHM_BBR_V3` in the preview API. The
controller shares BBR's delivery-rate sampler, transport accounting, and
recovery callbacks, with its probing and congestion model kept in
`BBR_V3_MODEL`. CUBIC remains the default.

The algorithm reference is the experimental
[IETF BBR draft](https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-06.html).
The [Google BBR v3 implementation](https://github.com/google/bbr/tree/v3)
provides an additional reference for the short-term bandwidth/inflight bounds
and ProbeBW cycle. The preview is still subject to interoperability and WAN
performance evaluation; passing deterministic unit tests is not a claim of
fairness or throughput on real networks.

## Controller invariants

- Loss samples retain the flight size, cumulative loss count, and probing state
  from transmission. Loss of a small final flight does not replace the long-term
  capacity estimate with the remaining bytes at loss-detection time.
- Short-term bandwidth and inflight limits adapt once per packet round outside
  bandwidth probing. Clean ACKs preserve those limits; entering REFILL clears
  them so that newly available capacity can be discovered.
- DOWN drains the queue, CRUISE waits before the next probe, REFILL waits for a
  packet round, and UP increases the probing limit. The probe interval combines
  a randomized two-to-three-second timer with a packet-round bound.
- ACK aggregation and startup growth precede the model's congestion-window
  limits. CRUISE leaves headroom below the long-term inflight limit.
- Pacing converts the bandwidth sample to bytes over the elapsed microseconds.
  The send quantum is a millisecond budget, capped at 64 KiB.
- ProbeRTT has a five-second freshness clock separate from the ten-second
  minimum-RTT filter. Its target is half a BDP with a four-packet floor; exit
  requires both a packet round and 200 ms at low inflight.
- Spurious recovery restores the saved limits and state. A path reset clears
  its model while preserving cumulative loss accounting for outstanding packets.
- Controllers without an ECN response do not mark outgoing packets ECT.

## Validation

`BbrTest.cpp` covers the shared BBR behavior and BBRv3 pacing, phases, loss
thresholds, bandwidth limits, and RTT probing. `BbrV3Test.cpp` exercises the
transport metadata and recovery boundaries. `EcnTest.cpp` covers ECN eligibility
for CUBIC, BBR, and BBRv3.

Use the existing `scripts/emulated-performance.ps1` with
`-CongestionControl cubic,bbr,bbrv3` on a machine with DuoNic configured for
controlled WAN measurements; see the [performance guide](../src/perf/readme.md).
