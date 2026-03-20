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

**Guidance for the user**
- Ignore the failure if it is a rare occurence
- Consider increasing the `MaxWorkerQueueDelayUs` for tests otherwise


**References**:
- GitHub issue: https://github.com/microsoft/msquic/issues/5835
- Failing test: `AppData/WithSendArgs.Send/353`
- CI config: `BVT-Debug-windows-windows-2025-x64-quictls-UseXdp-UseQtip`
