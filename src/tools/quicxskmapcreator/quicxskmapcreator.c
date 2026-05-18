/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Creates an XSKMAP, duplicates the handle into a QUIC server process, and
    attaches an XDP program with QUIC-aware match rules once the consumer
    signals it has inserted its XSKs.

    This tool is the "creator" half of the XSKMAP creator/consumer pattern
    for MsQuic. The consumer is typically quicsample running with
    -xdp -xdp_map_ifindex (Phase 2) or the MsQuic datapath itself (Phase 3).

    Usage:
        1. Start the QUIC server:
           quicsample -server -cert_hash:<hash> -xdp -xdp_map_ifindex:<N>
        2. Run this tool:
           quicxskmapcreator -TargetPid <PID> -IfIndex <N> -UdpPort <port>
        3. Paste the printed handle value into the consumer's stdin
        4. Press Enter here to attach the XDP program

    The creator owns the map and the XDP program lifetime.

--*/

#define _CRT_SECURE_NO_WARNINGS 1
#define XDP_API_VERSION 3
#define XDP_INCLUDE_WINCOMMON

#pragma warning(disable:5105)
#include <xdp/wincommon.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xdpapi.h>

#define LOGERR(...) \
    fprintf(stderr, "ERR: "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n")

//
// Must match QUIC_CID_PID_LENGTH in src/core/cid.h. The CIBIR data in
// MsQuic CIDs lives at offset CidServerIdLength + QUIC_CID_PID_LENGTH.
//
#define QUIC_CID_PID_LENGTH 2

static UINT32 TargetPid;
static UINT32 IfIndex;
static UINT16 UdpPort;
static UINT8 CidServerIdLength;
static BOOLEAN HasCibirId;
static UINT8 CibirIdData[6];
static UINT8 CibirIdLength;

static UINT8
DecodeHexChar(
    char c
    )
{
    if (c >= '0' && c <= '9') return (UINT8)(c - '0');
    if (c >= 'A' && c <= 'F') return (UINT8)(10 + c - 'A');
    if (c >= 'a' && c <= 'f') return (UINT8)(10 + c - 'a');
    return 0;
}

static UINT32
DecodeHexBuffer(
    const char* Hex,
    UINT32 OutLen,
    UINT8* Out
    )
{
    UINT32 Len = (UINT32)strlen(Hex) / 2;
    if (Len > OutLen) {
        Len = OutLen;
    }
    for (UINT32 i = 0; i < Len; i++) {
        Out[i] = (DecodeHexChar(Hex[i * 2]) << 4) | DecodeHexChar(Hex[i * 2 + 1]);
    }
    return Len;
}

static void
PrintUsage(void)
{
    printf(
        "quicxskmapcreator.exe -TargetPid <PID> -IfIndex <N> -UdpPort <port> [OPTIONS]\n"
        "\n"
        "Creates an XSKMAP, duplicates it into the target QUIC server process, and\n"
        "attaches an XDP program with QUIC-aware match rules.\n"
        "\n"
        "OPTIONS:\n"
        "   -TargetPid <PID>    PID of the consumer process (required)\n"
        "   -IfIndex <N>        Network interface index (required)\n"
        "   -UdpPort <port>     QUIC server UDP port (required)\n"
        "   -CibirId <hex>      CIBIR ID (hex: first byte is offset, rest is CID prefix)\n"
        "                       Example: -CibirId 00AABBCCDD\n"
        "   -CidServerIdLength <N>\n"
        "                       Server ID length in MsQuic CIDs (default: 0).\n"
        "                       Must match MsQuicLib.CidServerIdLength (non-zero when\n"
        "                       load balancing is enabled).\n"
    );
}

static BOOLEAN
ParseArgs(
    int ArgC,
    char** ArgV
    )
{
    int i = 1;
    TargetPid = 0;
    IfIndex = MAXUINT32;
    UdpPort = 0;
    CidServerIdLength = 0;
    HasCibirId = FALSE;

    while (i < ArgC) {
        if (!_stricmp(ArgV[i], "-TargetPid") || !_stricmp(ArgV[i], "-pid")) {
            if (++i >= ArgC) {
                LOGERR("Missing TargetPid value");
                return FALSE;
            }
            TargetPid = (UINT32)atoi(ArgV[i]);
        } else if (!_stricmp(ArgV[i], "-IfIndex")) {
            if (++i >= ArgC) {
                LOGERR("Missing IfIndex value");
                return FALSE;
            }
            IfIndex = (UINT32)atoi(ArgV[i]);
        } else if (!_stricmp(ArgV[i], "-UdpPort")) {
            if (++i >= ArgC) {
                LOGERR("Missing UdpPort value");
                return FALSE;
            }
            UdpPort = (UINT16)atoi(ArgV[i]);
        } else if (!_stricmp(ArgV[i], "-CidServerIdLength")) {
            if (++i >= ArgC) {
                LOGERR("Missing CidServerIdLength value");
                return FALSE;
            }
            CidServerIdLength = (UINT8)atoi(ArgV[i]);
        } else if (!_stricmp(ArgV[i], "-CibirId")) {
            if (++i >= ArgC) {
                LOGERR("Missing CibirId value");
                return FALSE;
            }
            UINT8 CibirRaw[7]; // offset (1 byte) + max 6 bytes CID
            UINT32 CibirRawLen = DecodeHexBuffer(ArgV[i], sizeof(CibirRaw), CibirRaw);
            if (CibirRawLen < 2) {
                LOGERR("CIBIR ID too short (need at least offset + 1 byte CID)");
                return FALSE;
            }
            CibirIdLength = (UINT8)(CibirRawLen - 1);
            memcpy(CibirIdData, &CibirRaw[1], CibirIdLength);
            HasCibirId = TRUE;
        } else {
            LOGERR("Unexpected parameter \"%s\"", ArgV[i]);
            return FALSE;
        }
        ++i;
    }

    if (TargetPid == 0) {
        LOGERR("-TargetPid is required");
        return FALSE;
    }
    if (IfIndex == MAXUINT32) {
        LOGERR("-IfIndex is required");
        return FALSE;
    }
    if (UdpPort == 0) {
        LOGERR("-UdpPort is required");
        return FALSE;
    }

    return TRUE;
}

int
__cdecl
main(
    int argc,
    char** argv
    )
{
    XDP_STATUS XdpStatus;
    HANDLE XskMap = NULL;
    HANDLE TargetProcess = NULL;
    HANDLE RemoteHandle = NULL;
    HANDLE Program = NULL;

    if (!ParseArgs(argc, argv)) {
        PrintUsage();
        return 1;
    }

    //
    // Stage 1: Create the XSKMAP.
    //
    XdpStatus = XdpMapCreate(&XskMap, XDP_MAP_TYPE_XSKMAP);
    if (FAILED(XdpStatus)) {
        LOGERR("XdpMapCreate failed: 0x%x", XdpStatus);
        return 1;
    }

    printf("[Stage 1] Created XSKMAP (local handle: 0x%IX)\n", (UINT_PTR)XskMap);

    //
    // Stage 2: Duplicate the map handle into the consumer process.
    //
    TargetProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, TargetPid);
    if (TargetProcess == NULL) {
        LOGERR("OpenProcess(%u) failed: %u. Ensure the consumer is running.",
            TargetPid, GetLastError());
        CloseHandle(XskMap);
        return 1;
    }

    if (!DuplicateHandle(
            GetCurrentProcess(),
            XskMap,
            TargetProcess,
            &RemoteHandle,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS)) {
        LOGERR("DuplicateHandle failed: %u", GetLastError());
        CloseHandle(TargetProcess);
        CloseHandle(XskMap);
        return 1;
    }

    CloseHandle(TargetProcess);

    printf("[Stage 2] Duplicated XSKMAP into PID %u. Remote handle: 0x%IX\n",
        TargetPid, (UINT_PTR)RemoteHandle);
    printf("\n");
    printf("  Paste 0x%IX into the consumer, let it insert its XSKs.\n",
        (UINT_PTR)RemoteHandle);
    printf("\n");

    //
    // Stage 3: Wait for user signal that the consumer is ready.
    //
    printf("[Stage 3] Press ENTER when the consumer has inserted its XSKs...\n");
    fflush(stdout);
    (void)getchar();

    //
    // Stage 4: Attach the XDP program with QUIC-aware match rules.
    //
    {
        const XDP_HOOK_ID XdpInspectRxL2 = {
            XDP_HOOK_L2,
            XDP_HOOK_RX,
            XDP_HOOK_INSPECT,
        };

        XDP_RULE Rules[2];
        UINT32 RuleCount = 0;
        ZeroMemory(Rules, sizeof(Rules));

        if (HasCibirId) {
            //
            // CIBIR mode: match on QUIC connection IDs. The CID offset must
            // match MsQuic's CID layout: CidServerIdLength + QUIC_CID_PID_LENGTH.
            //
            UINT8 CidOffset = CidServerIdLength + QUIC_CID_PID_LENGTH;

            Rules[RuleCount].Match = XDP_MATCH_QUIC_FLOW_SRC_CID;
            Rules[RuleCount].Pattern.QuicFlow.UdpPort = htons(UdpPort);
            Rules[RuleCount].Pattern.QuicFlow.CidLength = CibirIdLength;
            Rules[RuleCount].Pattern.QuicFlow.CidOffset = CidOffset;
            memcpy(Rules[RuleCount].Pattern.QuicFlow.CidData, CibirIdData, CibirIdLength);
            Rules[RuleCount].Action = XDP_PROGRAM_ACTION_REDIRECT;
            Rules[RuleCount].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSKMAP_BY_QUEUEID;
            Rules[RuleCount].Redirect.Target = XskMap;
            RuleCount++;

            Rules[RuleCount].Match = XDP_MATCH_QUIC_FLOW_DST_CID;
            Rules[RuleCount].Pattern.QuicFlow.UdpPort = htons(UdpPort);
            Rules[RuleCount].Pattern.QuicFlow.CidLength = CibirIdLength;
            Rules[RuleCount].Pattern.QuicFlow.CidOffset = CidOffset;
            memcpy(Rules[RuleCount].Pattern.QuicFlow.CidData, CibirIdData, CibirIdLength);
            Rules[RuleCount].Action = XDP_PROGRAM_ACTION_REDIRECT;
            Rules[RuleCount].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSKMAP_BY_QUEUEID;
            Rules[RuleCount].Redirect.Target = XskMap;
            RuleCount++;
        } else {
            //
            // Simple mode: match on UDP destination port.
            //
            Rules[RuleCount].Match = XDP_MATCH_UDP_DST;
            Rules[RuleCount].Pattern.Port = htons(UdpPort);
            Rules[RuleCount].Action = XDP_PROGRAM_ACTION_REDIRECT;
            Rules[RuleCount].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSKMAP_BY_QUEUEID;
            Rules[RuleCount].Redirect.Target = XskMap;
            RuleCount++;
        }

        XdpStatus =
            XdpCreateProgram(
                IfIndex,
                &XdpInspectRxL2,
                0,
                XDP_CREATE_PROGRAM_FLAG_ALL_QUEUES,
                Rules,
                RuleCount,
                &Program);
        if (FAILED(XdpStatus)) {
            LOGERR("XdpCreateProgram failed: 0x%x", XdpStatus);
            CloseHandle(XskMap);
            return 1;
        }
    }

    printf("[Stage 4] XDP program attached on IfIndex %u\n", IfIndex);
    if (HasCibirId) {
        UINT8 CidOffset = CidServerIdLength + QUIC_CID_PID_LENGTH;
        printf("  Rules: XDP_MATCH_QUIC_FLOW_SRC_CID + XDP_MATCH_QUIC_FLOW_DST_CID\n");
        printf("  UdpPort: %u, CidOffset: %u (SidLen=%u + PidLen=%u), CidLength: %u\n",
            UdpPort, CidOffset, CidServerIdLength, QUIC_CID_PID_LENGTH, CibirIdLength);
    } else {
        printf("  Rule: XDP_MATCH_UDP_DST, Port: %u\n", UdpPort);
    }
    printf("  Target: XDP_REDIRECT_TARGET_TYPE_XSKMAP_BY_QUEUEID\n");
    printf("\n");
    printf("Press ENTER to detach the program and exit.\n");
    fflush(stdout);
    (void)getchar();

    //
    // Cleanup: closing the program handle detaches XDP. Closing the map
    // handle releases our reference (consumer may still hold one).
    //
    printf("Detaching XDP program and cleaning up.\n");
    CloseHandle(Program);
    CloseHandle(XskMap);

    return 0;
}
