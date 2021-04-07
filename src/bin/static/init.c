#include "quic_platform.h"

void
MsQuicLibraryLoad(
    void
    );

void
MsQuicLibraryUnload(
    void
    );

void
MsQuicLoad(
    void
    )
{
    CxPlatSystemLoad();
    MsQuicLibraryLoad();
}

void
MsQuicUnload(
    void
    )
{
    MsQuicLibraryUnload();
    CxPlatSystemUnload();
}

