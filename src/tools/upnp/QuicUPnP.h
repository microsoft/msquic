/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct QUIC_UPNP QUIC_UPNP;

//
// Initialization function for UPnP logic. Start the asynchronous process of
// attempting to open up the specified UDP port.
//
QUIC_UPNP* QuicUPnPInitialize(void);

//
// Cleans up the UPnP handle returned from QuicUPnPInitialize. This function may
// block to wait and clean up any internal threads.
//
void QuicUPnPUninitialize(QUIC_UPNP* UPnP);

//
// Prints the set of statically configured UPnP mappings to the console.
//
void QuicUPnPDumpStaticMappings(QUIC_UPNP* UPnP);

//
// Adds a static UPnP mapping. Returns 0 on success.
//
int
QuicUPnPAddStaticMapping(
    QUIC_UPNP* UPnP,
    const char* Protocol,
    const char* ExternalIP,
    uint16_t ExternalPort,
    const char* InternalIP,
    uint16_t InternalPort,
    const char* Description
    );

//
// Removes a static UPnP mapping. Returns 0 on success.
//
int
QuicUPnPRemoveStaticMapping(
    QUIC_UPNP* UPnP,
    const char* Protocol,
    uint16_t ExternalPort
    );

#if defined(__cplusplus)
}
#endif
