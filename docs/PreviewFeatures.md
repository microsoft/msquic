Preview features
=========

New features are phased in to the MsQuic library in a staged manner to enable gradual roll in, when each of these features are deemed ready for wider use.

These features are first made available in a library-wide **Preview mode** till they are made part of the mainstream MsQuic library functionality.

## QUIC_API_ENABLE_PREVIEW_FEATURES

Preview feature source code is placed within c pre-processor conditional sections that are enabled using the QUIC_API_ENABLE_PREVIEW_FEATURES macro, to isolate it from the rest of the established code.

This macro is declared in code and set to be enabled by default. Users can change this macro per their deployment needs and recompile the code to include or exclude the preview features.

## Current list of Preview features

### Reliable Reset Negotiated

### Oneway Delay Negotiated

### Network Statistics



