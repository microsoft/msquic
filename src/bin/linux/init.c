/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Library init routines

--*/

void MsQuicLibraryLoad(void);

//
// This function only exists to ensure the static libraries are loaded into the
// shared object. This function cannot be called, and is not exported from the
// library
//
void QuicSharedCallOpen() { MsQuicLibraryLoad(); }
