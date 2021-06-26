/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Injection hooks used by msquic_fuzz to provide fuzzers with the ability
    to read and modify quic payloads before they are encrypted.

--*/

#ifdef QUIC_FUZZER

#include "precomp.h"

#include "msquic_fuzz.h"
#ifdef QUIC_CLOG
#include "injection.c.clog.h"
#endif

__declspec(noinline)
void
QuicFuzzInjectHook(
    _Inout_ QUIC_PACKET_BUILDER *Builder
    )
{
   //
   // This CPUID is used to raise a signal to the emulated fuzzer (TKO)
   // to signal that the target is in a state where pre-encryption
   // payload data can be read from the virtual machine.
   //
   CXPLAT_CPUID(0x7b3c3639, 0, 0, 0, 0);

#pragma warning(push) // Don't care about OACR warnings for test-only injection code.
#pragma warning(disable:26007)

   if (MsQuicFuzzerContext.InjectCallback) {
      MsQuicFuzzerContext.InjectCallback(
         MsQuicFuzzerContext.CallbackContext,
         Builder->Datagram->Buffer,
         Builder->Datagram->Length,
         Builder->HeaderLength,
         &Builder->Datagram->Buffer,
         &Builder->DatagramLength);

      Builder->Datagram->Length = Builder->DatagramLength;
   }

#pragma warning(pop)
}

#endif // QUIC_FUZZER
