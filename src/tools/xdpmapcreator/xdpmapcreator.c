/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Creates an XSKMAP, duplicates the handle into a target process, and
    attaches an XDP program once the consumer signals it has inserted its XSKs.

    Usage:
        1. Start xdpmapconsumer.exe -IfIndex <N> -QueueCount <N> (prints PID)
        2. Run: xdpmapcreator.exe -TargetPid <PID> -IfIndex <N> [-IcmpOnly]
        3. Paste the printed handle value into the consumer's stdin
        4. Once the consumer has inserted its XSKs, press Enter here to
           attach the XDP program and start steering traffic.

    The creator owns the map and the XDP program lifetime.

--*/

#define _CRT_SECURE_NO_WARNINGS 1
#define XDP_API_VERSION 3
#define XDP_INCLUDE_WINCOMMON

#pragma warning(disable:5105)
#include <xdp/wincommon.h>
#include <stdio.h>
#include <stdlib.h>

#include <xdpapi.h>

#define LOGERR(...) \
    fprintf(stderr, "ERR: "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n")

static UINT32 TargetPid;
static UINT32 IfIndex;
static BOOLEAN UseIcmpMatch;

static void
PrintUsage(void)
{
    printf(
        "xdpmapcreator.exe -TargetPid <PID> -IfIndex <N> [OPTIONS]\n"
        "\n"
        "Creates an XSKMAP, duplicates it into the target process, and attaches\n"
        "an XDP program once you signal readiness.\n"
        "\n"
        "OPTIONS:\n"
        "   -TargetPid <PID>    PID of the consumer process (required)\n"
        "   -IfIndex <N>        Network interface index (required)\n"
        "   -IcmpOnly           Match only ICMPv4 traffic (default: match all)\n"
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
    UseIcmpMatch = FALSE;

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
        } else if (!_stricmp(ArgV[i], "-IcmpOnly")) {
            UseIcmpMatch = TRUE;
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
    printf("  Paste 0x%IX into the consumer, let it create and insert its XSKs.\n",
        (UINT_PTR)RemoteHandle);
    printf("\n");

    //
    // Stage 3: Wait for user signal that the consumer is ready.
    //
    printf("[Stage 3] Press ENTER when the consumer has inserted its XSKs...\n");
    fflush(stdout);
    (void)getchar();

    //
    // Stage 4: Attach the XDP program with the now-populated map.
    //
    {
        const XDP_HOOK_ID XdpInspectRxL2 = {
            XDP_HOOK_L2,
            XDP_HOOK_RX,
            XDP_HOOK_INSPECT,
        };

        XDP_RULE Rule;
        ZeroMemory(&Rule, sizeof(Rule));

        if (UseIcmpMatch) {
            Rule.Match = XDP_MATCH_IP_NEXT_HEADER;
            Rule.Pattern.NextHeader = 1; // IPPROTO_ICMP
        } else {
            Rule.Match = XDP_MATCH_ALL;
        }

        Rule.Action = XDP_PROGRAM_ACTION_REDIRECT;
        Rule.Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSKMAP_BY_QUEUEID;
        Rule.Redirect.Target = XskMap;

        XdpStatus =
            XdpCreateProgram(
                IfIndex,
                &XdpInspectRxL2,
                0,
                XDP_CREATE_PROGRAM_FLAG_ALL_QUEUES,
                &Rule,
                1,
                &Program);
        if (FAILED(XdpStatus)) {
            LOGERR("XdpCreateProgram failed: 0x%x", XdpStatus);
            CloseHandle(XskMap);
            return 1;
        }
    }

    printf("[Stage 4] XDP program attached on IfIndex %u (%s). Traffic is flowing!\n",
        IfIndex, UseIcmpMatch ? "ICMPv4 only" : "all traffic");
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
