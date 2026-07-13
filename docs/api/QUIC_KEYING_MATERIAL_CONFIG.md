QUIC_KEYING_MATERIAL_CONFIG structure
======

The structure used to configure a call to [ConnectionExportKeyingMaterial](ConnectionExportKeyingMaterial.md).

> **Note** - This API is in [preview](../PreviewFeatures.md). It should be considered unstable and can be subject to breaking changes.

# Syntax

```C
typedef struct QUIC_KEYING_MATERIAL_CONFIG {
    _Field_z_ const char* Label;
    uint32_t ContextLength;
    _Field_size_bytes_opt_(ContextLength) const uint8_t* Context;
    uint32_t OutputLength;
} QUIC_KEYING_MATERIAL_CONFIG;
```

# Members

`Label`

A non-NULL, null-terminated ASCII string that disambiguates the exported keying material between different uses. Both peers must use the same label to derive the same material. See [RFC 5705](https://www.rfc-editor.org/rfc/rfc5705) for guidance on choosing a label.

`ContextLength`

The length, in bytes, of the buffer pointed to by `Context`. May be 0.

`Context`

An optional pointer to a `ContextLength`-byte context buffer that is mixed into the derivation, further scoping the exported material. May be NULL, in which case `ContextLength` must be 0.

`OutputLength`

The number of bytes of keying material to export. Must be non-zero. The `Output` buffer passed to [ConnectionExportKeyingMaterial](ConnectionExportKeyingMaterial.md) must be at least this large.

# Remarks

Both peers of a connection derive identical keying material for the same `Label` and `Context`. Different labels or contexts produce independent, unrelated material.

# See Also

[ConnectionExportKeyingMaterial](ConnectionExportKeyingMaterial.md)<br>
