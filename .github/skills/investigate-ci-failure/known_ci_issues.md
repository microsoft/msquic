# Known CI Issues

Reference catalog of previously investigated CI failures. When investigating a
new failure, check this file first — the symptom pattern may match a known issue.

---

## 1. Worker Queue Delay Overload — `CONNECTION_REFUSED` (0x800704c9)

**Symptom**:
- Test fails with `Unexpected transport Close Error, expected=0x0, actual=0x800704c9`
- Followed by `Connection->GetTransportClosed() not false`
- Followed by timeout waiting for clients to complete
- Affects multi-connection tests (ConnectionCount > 1)

**Error code**: `QUIC_STATUS_CONNECTION_REFUSED` = `0x800704c9` (HRESULT for
`ERROR_CONNECTION_REFUSED`). This is a QUIC-level transport error code 0x02, NOT
a socket-level error.

**Root cause**: CI runner CPU contention causes the MsQuic worker thread to be
repeatedly descheduled by the OS (many gaps of 100–300ms each). While the worker
processes one connection, other connections sit in the queue. The EMA-based
`AverageQueueDelay` spikes past the default 250ms threshold
(`MaxWorkerQueueDelayUs`). When the next connection arrives at the listener, it
is rejected at `listener.c:822-824` with `CONNECTION_REFUSED`.

**Key trace evidence** (what to look for in `quic.log`):
1. `QueueDelay` values on the test registration's worker climbing rapidly
   (e.g., 91K → 262K → 452K μs)
2. Large timestamp gaps (100ms+) between consecutive events on the same
   worker thread, indicating OS descheduling
3. `"Connection rejected by registration (overloaded)."` log entry

**Code path**: `listener.c:814` → `QuicRegistrationAcceptConnection` →
`registration.c:476` → `QuicWorkerIsOverloaded` → checks
`Worker->AverageQueueDelay > MsQuicLib.Settings.MaxWorkerQueueDelayUs`

---

## 2. Windows CryptoAPI Stall — Watchdog Timeout During Certificate Operations

**Symptom**:
- Test crashes with exit code `-1073740768` (`0xC0000420` /
  `STATUS_ASSERTION_FAILURE`)
- Log contains `"Watchdog timeout fired!"` from `msquic.hpp`
- Failure occurs during `CONFIGURATION_LOAD_CREDENTIAL` or any operation
  that triggers Windows certificate chain verification
- The same test passes on retry or on other CI runs

**Root cause**: Windows CryptoAPI certificate chain verification
(`CertVerifyCertificateChainPolicy` and related APIs) can stall for
multiple seconds on CI runners. This typically happens when the OS CRL
(Certificate Revocation List) cache expires and the system attempts a
network call to a CRL distribution point. On CI runners with constrained
or variable network connectivity, this call can take 2–5+ seconds instead
of the usual <100ms.

Any test that uses a `CxPlatWatchdog` with a tight timeout (e.g., 2000ms)
and performs TLS certificate loading or handshake operations is susceptible.
The stall is not specific to any particular test — it affects whichever
iteration or test happens to trigger the CRL cache miss.

**Key trace evidence** (what to look for in `quic.log`):
1. A `CONFIGURATION_LOAD_CREDENTIAL` event or TLS handshake step with an
   unusually long gap before the next event (2+ seconds vs. typical <100ms)
2. `Exported chain verification result: 2148204809` (`0x800B0109` /
   `CERT_E_UNTRUSTEDROOT`) — expected for self-signed test certs, but the
   latency is abnormal
3. Watchdog assertion firing shortly after the slow verification completes

**Affected tests**: Any test using `CxPlatWatchdog` with a timeout ≤ 2–3
seconds that also loads TLS credentials or performs handshakes. Examples:
- `Basic.ConnectionCloseFromCallback` (watchdog: 2000ms)
- Other tests with tight watchdog timeouts that iterate over multiple
  TLS configurations
