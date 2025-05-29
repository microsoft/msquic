Preview features
=========
> [!IMPORTANT]
>
> Preview features are recently included features in the MsQuic library.
>
> The API for the preview features should be considered unstable / not fully baked in / subject to change.
>
> Please be aware of these additional risks before using the preview feature API.
>

New features added to the MsQuic library are exposed through newly added API as a preview, for stabilization and gradual adoption.

These new API are first made available in the export headers only in the **Preview mode**. The underlying functionality is still present in the MsQuic library but is unreachable through regular API.

When a new feature is deemed ready for wider use, its API is moved from the preview portion to the regular portion of MsQuic library headers.

## QUIC_API_ENABLE_PREVIEW_FEATURES

A preview feature's API declarations (typically in msquic.h) are placed within pre-processor conditional sections that are enabled using the QUIC_API_ENABLE_PREVIEW_FEATURES macro, to isolate it from the rest of the established API.

Any application wanting to use the preview features must declare this macro (and set it to 1) before including the MsQuic headers.

## Current list of Preview features

### Reliable Reset Negotiated

TODO

### Oneway Delay Negotiated

TODO

### Network Statistics

TODO

### StreamProvideReceiveBuffers

[StreamProvideReceiveBuffers](StreamProvideReceiveBuffers.md)

TODO

### Asynchronous Close APIs

MsQuic now provides asynchronous alternatives to the synchronous close functions to avoid deadlocks in single-threaded execution environments:

- [RegistrationCloseAsync](api/RegistrationCloseAsync.md) - Asynchronously closes a registration handle
- [CloseAsync](api/CloseAsync.md) - Asynchronously cleans up the function table and releases the library reference

These APIs are particularly useful in scenarios where synchronous close operations might cause deadlocks, such as when closing objects from within MsQuic callbacks or in single-threaded execution environments.
