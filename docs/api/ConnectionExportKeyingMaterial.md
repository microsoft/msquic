ConnectionExportKeyingMaterial function
======

Exports keying material derived from the connection's TLS session, as described in [RFC 5705](https://www.rfc-editor.org/rfc/rfc5705) and [RFC 8446 Section 7.5](https://www.rfc-editor.org/rfc/rfc8446#section-7.5). The exported material is bound to the TLS session and can be used by the app for its own purposes (for example, to authenticate the peer at the application layer).

> **Note** - This is a preview API and is only available when the library is built with `QUIC_API_ENABLE_PREVIEW_FEATURES`. It is available from v2.6.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_CONNECTION_EXPORT_KEYING_MATERIAL_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ _Pre_defensive_ const QUIC_KEYING_MATERIAL_CONFIG* Config,
    _Out_writes_bytes_(Config->OutputLength)
        uint8_t* Output
    );
```

# Parameters

`Connection`

The valid handle to an open and connected connection object.

`Config`

A pointer to a [QUIC_KEYING_MATERIAL_CONFIG](QUIC_KEYING_MATERIAL_CONFIG.md) that specifies the label, optional context, and the number of bytes to export.

`Output`

A caller-allocated buffer of at least `Config->OutputLength` bytes that receives the exported keying material on success. Its contents are undefined if the call fails.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

The following errors are the most likely to be returned:

`QUIC_STATUS_SUCCESS`

The keying material was exported into `Output`.

`QUIC_STATUS_INVALID_PARAMETER`

`Config`, `Config->Label`, or `Output` is NULL; `Config->OutputLength` is 0; `Config->Context` is NULL while `Config->ContextLength` is non-zero; or `Connection` is not a connection handle.

`QUIC_STATUS_INVALID_STATE`

The connection's TLS context is no longer available. This happens if the handshake has not completed yet, or if it has already been released after handshake completion (see Remarks).

`QUIC_STATUS_NOT_SUPPORTED`

The underlying TLS provider does not support exporting keying material. This is the case in kernel mode.

# Remarks

The keying material can only be exported while the connection's TLS context is alive. The context is created during the handshake and, when session resumption is disabled, is released shortly after the handshake completes (once the handshake `CRYPTO` data is fully acknowledged), mirroring the behavior of `QUIC_PARAM_TLS_HANDSHAKE_INFO`.

The guaranteed-safe window to call this API is inline while handling the `QUIC_CONNECTION_EVENT_CONNECTED` event. Calling it later may return `QUIC_STATUS_INVALID_STATE` if the context has already been released.

The call is blocking. When invoked from the connection's worker thread (for example, inline in a connection event callback) it executes synchronously; otherwise it is queued to the connection's worker and the calling thread blocks until the operation completes.

Both peers of a connection derive identical keying material for the same `Label` and `Context`. Different labels or contexts produce independent, unrelated material.

This API is only supported by the user-mode TLS providers (Schannel and OpenSSL/quictls). In kernel mode it returns `QUIC_STATUS_NOT_SUPPORTED`.

# See Also

[QUIC_KEYING_MATERIAL_CONFIG](QUIC_KEYING_MATERIAL_CONFIG.md)<br>
[QUIC_CONNECTION_EVENT](QUIC_CONNECTION_EVENT.md)<br>
[ConnectionOpen](ConnectionOpen.md)<br>
[ConnectionStart](ConnectionStart.md)<br>
[ConnectionClose](ConnectionClose.md)<br>
