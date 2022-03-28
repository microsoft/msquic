/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/


//
// Test code defaults to disabling certificate validation.
//
#define QUIC_DEFAULT_CLIENT_CRED_FLAGS \
    (QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)

#ifndef _KERNEL_MODE
#include <vector>
#endif

#include "TestAbstractionLayer.h"

#include "msquic.h"
#include "msquicp.h"
#include "quic_versions.h"
#include "quic_trace.h"

#ifdef _KERNEL_MODE
#ifdef PAGEDX
#undef PAGEDX
#endif
#ifdef INITCODE
#undef INITCODE
#endif
#ifndef WIN_ASSERT
#define WIN_ASSERT CXPLAT_FRE_ASSERT
#endif
#include "karray.h"
#endif

#include "TestHelpers.h"
#include "TestStream.h"
#include "TestConnection.h"
#include "TestListener.h"
#include "DrillDescriptor.h"

extern bool UseDuoNic;

//
// Override the SDK version of QUIC_LOCALHOST_FOR_AF to use duonic instead of localhost when desired.
//
#ifdef _MSQUIC_WINUSER_
#undef QUIC_LOCALHOST_FOR_AF
#define QUIC_LOCALHOST_FOR_AF(Af) (UseDuoNic ? ((Af == QUIC_ADDRESS_FAMILY_INET) ? "192.168.1.11" : "fc00::1:11") : "localhost")
#endif // _MSQUIC_WINUSER_

//
// Set a QUIC_ADDR to the duonic "server" address.
//
inline
void
QuicAddrSetToDuoNic(
    _Inout_ QUIC_ADDR* Addr
    )
{
    if (QuicAddrGetFamily(Addr) == QUIC_ADDRESS_FAMILY_INET) {
        // 192.168.1.11
        ((uint32_t*)&(Addr->Ipv4.sin_addr))[0] = 184658112;
    } else {
        // fc00::1:11
        ((uint16_t*)&(Addr->Ipv6.sin6_addr))[0] = 252;
        ((uint16_t*)&(Addr->Ipv6.sin6_addr))[1] = 0;
        ((uint16_t*)&(Addr->Ipv6.sin6_addr))[2] = 0;
        ((uint16_t*)&(Addr->Ipv6.sin6_addr))[3] = 0;
        ((uint16_t*)&(Addr->Ipv6.sin6_addr))[4] = 0;
        ((uint16_t*)&(Addr->Ipv6.sin6_addr))[5] = 0;
        ((uint16_t*)&(Addr->Ipv6.sin6_addr))[6] = 256;
        ((uint16_t*)&(Addr->Ipv6.sin6_addr))[7] = 4352;
    }
}
