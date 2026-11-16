ConnectionExportKeyingMaterial function
======

Exports keying material derived from the connection's TLS session, as described in [RFC 5705](https://www.rfc-editor.org/rfc/rfc5705) and [RFC 8446 Section 7.5](https://www.rfc-editor.org/rfc/rfc8446#section-7.5).
The exported material is bound to the TLS session and can be used by the app for its own purposes (for example, to authenticate the peer at the application layer).

> **Note** - This API is in [preview](../PreviewFeatures.md). It should be considered unstable and can be subject to breaking changes.

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

Value | Meaning
--- | ---
**QUIC_STATUS_SUCCESS** | The keying material was exported into `Output`.
**QUIC_STATUS_INVALID_PARAMETER** | `Config`, `Config->Label`, or `Output` is NULL; `Config->OutputLength` is 0; `Config->Context` is NULL while `Config->ContextLength` is non-zero; or `Connection` is not a connection handle.
**QUIC_STATUS_INVALID_STATE** | The connection's TLS context is no longer available. This happens if the handshake has not completed yet, or if it has already been released after handshake completion (see Remarks).
**QUIC_STATUS_NOT_SUPPORTED** | The underlying TLS provider does not support exporting keying material. This is the case in kernel mode.

# Remarks

The keying material can only be exported once the handshake is completed and while the connection's TLS context is alive.
On a server, the TLS context is is released shortly after the handshake completes (unless resumption tickets are used)

This API is best called inline while handling the `QUIC_CONNECTION_EVENT_CONNECTED` event to ensure the TLS context is still alive.
Calling it later may return `QUIC_STATUS_INVALID_STATE` if the context has already been released.

This API is not supported for Windows Kernel Mode, where it returns `QUIC_STATUS_NOT_SUPPORTED`.

# See Also

[QUIC_KEYING_MATERIAL_CONFIG](QUIC_KEYING_MATERIAL_CONFIG.md)<br>
[QUIC_CONNECTION_EVENT](QUIC_CONNECTION_EVENT.md)<br>