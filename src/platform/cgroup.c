/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

    Implementation uses from .NET with MIT license

Abstract:

    Read the memory limit for the current process

Environment:

    Posix

--*/

#ifdef __FreeBSD__
#define _WITH_GETLINE
#endif

#include "quic_platform.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/mount.h>
#include <sys/param.h>
#else
#include <sys/vfs.h>
#endif
#include <errno.h>

#ifndef SIZE_T_MAX
#define SIZE_T_MAX (~(size_t)0)
#endif

#define CGROUP2_SUPER_MAGIC 0x63677270
#define TMPFS_MAGIC 0x01021994

#define PROC_MOUNTINFO_FILENAME "/proc/self/mountinfo"
#define PROC_CGROUP_FILENAME "/proc/self/cgroup"
#define CGROUP1_MEMORY_LIMIT_FILENAME "/memory.limit_in_bytes"
#define CGROUP2_MEMORY_LIMIT_FILENAME "/memory.max"

static int CGroupVersion = 0;
static char* CGroupMemoryPath = NULL;

//
// Get memory size multiplier based on the passed in units (k = kilo, m = mega, g = giga)
//
static
uint64_t
GetMemorySizeMultiplier(
    _In_ char Units
    )
{
    switch(Units)
    {
        case 'g':
        case 'G': return 1024 * 1024 * 1024;
        case 'm':
        case 'M': return 1024 * 1024;
        case 'k':
        case 'K': return 1024;
        default: return 1; // No units multiplier
    }
}

static
_Success_(return != FALSE)
BOOLEAN
ReadMemoryValueFromFile(
    _In_z_ const char* Filename,
    _Out_ uint64_t* MemValue)
{
    BOOLEAN Result = FALSE;
    char* Line = NULL;
    size_t LineLen = 0;
    char* EndPtr = NULL;
    uint64_t Num = 0, Multiplier;

    if (MemValue == NULL) {
        return FALSE;
    }

    FILE* File = fopen(Filename, "r");
    if (File == NULL) {
        goto Done;
    }

    if (getline(&Line, &LineLen, File) == -1) {
        goto Done;
    }

    errno = 0;
    Num = strtoull(Line, &EndPtr, 0);
    if (errno != 0) {
        goto Done;
    }

    Multiplier = GetMemorySizeMultiplier(*EndPtr);
    *MemValue = Num * Multiplier;
    Result = TRUE;
    if (*MemValue/Multiplier != Num) {
        Result = FALSE;
    }

Done:

    if (File) {
        fclose(File);
    }
    free(Line);
    return Result;
}

static
_Success_(return != FALSE)
BOOLEAN
IsCGroup1MemorySubsystem(
    _In_z_ const char *strTok
    )
{
    return strcmp("memory", strTok) == 0;
}

static
_Success_(return == 1 || return == 2)
int
FindCGroupVersion(
    void
    )
{
    //
    // It is possible to have both cgroup v1 and v2 enabled on a system.
    // Most non-bleeding-edge Linux distributions fall in this group. We
    // look at the file system type of /sys/fs/cgroup to determine which
    // one is the default. For more details, see:
    // https://systemd.io/CGROUP_DELEGATION/#three-different-tree-setups-
    // We dont care about the difference between the "legacy" and "hybrid"
    // modes because both of those involve cgroup v1 controllers managing
    // resources.
    //

    struct statfs Stats;
    int Result = statfs("/sys/fs/cgroup", &Stats);
    if (Result != 0) {
        return 0;
    }

    switch (Stats.f_type) {
        case TMPFS_MAGIC: return 1;
        case CGROUP2_SUPER_MAGIC: return 2;
        default: return 0;
    }
}

static
void
FindHierarchyMount(
    _In_ BOOLEAN (*IsSubsystem)(const char *),
    _Out_ char** MountPathOut,
    _Out_ char** MountRootOut
    )
{
    char *Line = NULL;
    size_t LineLen = 0, MaxLineLen = 0;
    char *FilesystemType = NULL;
    char *Options = NULL;
    char *MountPath = NULL;
    char *MountRoot = NULL;

    FILE *MountInfoFile = fopen(PROC_MOUNTINFO_FILENAME, "r");
    if (MountInfoFile == NULL) {
        goto Done;
    }

    while (getline(&Line, &LineLen, MountInfoFile) != -1) {
        if (FilesystemType == NULL || LineLen > MaxLineLen) {
            free(FilesystemType);
            FilesystemType = NULL;
            free(Options);
            Options = NULL;
            FilesystemType = (char*)malloc(LineLen+1);
            if (FilesystemType == NULL) {
                goto Done;
            }
            Options = (char*)malloc(LineLen+1);
            if (Options == NULL) {
                goto Done;
            }
            MaxLineLen = LineLen;
        }

        char* SeparatorChar = strstr(Line, " - ");

        //
        // See man page of proc to get format for /proc/self/mountinfo file
        //
        int SscanfRet = sscanf(SeparatorChar,
                                " - %s %*s %s",
                                FilesystemType,
                                Options);
        if (SscanfRet != 2) {
            goto Done;
        }

        if (strncmp(FilesystemType, "cgroup", 6) == 0) {
            BOOLEAN IsSubsystemMatch = IsSubsystem == NULL;
            if (!IsSubsystemMatch) {
                char* Context = NULL;
                char* StrTok = strtok_r(Options, ",", &Context);
                while (!IsSubsystemMatch && StrTok != NULL) {
                    IsSubsystemMatch = IsSubsystem(StrTok);
                    StrTok = strtok_r(NULL, ",", &Context);
                }
            }
            if (IsSubsystemMatch) {
                MountPath = (char*)malloc(LineLen+1);
                if (MountPath == NULL) {
                    goto Done;
                }
                MountRoot = (char*)malloc(LineLen+1);
                if (MountRoot == NULL) {
                    goto Done;
                }

                SscanfRet =
                    sscanf(
                        Line,
                        "%*s %*s %*s %s %s ",
                        MountRoot,
                        MountPath);
                if (SscanfRet != 2) {
                    goto Done;
                }

                //
                // assign the output arguments and clear the locals so we don't free them.
                //
                *MountPathOut = MountPath;
                *MountRootOut = MountRoot;
                MountPath = MountRoot = NULL;
                break;
            }
        }
    }

Done:

    free(MountPath);
    free(MountRoot);
    free(FilesystemType);
    free(Options);
    free(Line);
    if (MountInfoFile) {
        fclose(MountInfoFile);
    }
}

static
_Success_(return != NULL)
char*
FindCGroupPathForSubsystem(
    _In_ BOOLEAN (*IsSubsystem)(const char *)
    )
{
    char* Line = NULL;
    size_t LineLen = 0;
    size_t MaxLineLen = 0;
    char* SubsystemList = NULL;
    char* CGroupPath = NULL;
    BOOLEAN Result = FALSE;

    FILE *CGroupFile = fopen(PROC_CGROUP_FILENAME, "r");
    if (CGroupFile == NULL) {
        goto Done;
    }

    while (!Result && getline(&Line, &LineLen, CGroupFile) != -1) {
        if (SubsystemList == NULL || LineLen > MaxLineLen) {
            free(SubsystemList);
            SubsystemList = NULL;
            free(CGroupPath);
            CGroupPath = NULL;
            SubsystemList = (char*)malloc(LineLen+1);
            if (SubsystemList == NULL) {
                goto Done;
            }
            CGroupPath = (char*)malloc(LineLen+1);
            if (CGroupPath == NULL) {
                goto Done;
            }
            MaxLineLen = LineLen;
        }

        if (CGroupVersion == 1) {
            //
            // See man page of proc to get format for /proc/self/cgroup file
            //
            int SscanfRet = sscanf(Line,
                                    "%*[^:]:%[^:]:%s",
                                    SubsystemList,
                                    CGroupPath);
            if (SscanfRet != 2) {
                goto Done;
            }

            char* Context = NULL;
            char* StrTok = strtok_r(SubsystemList, ",", &Context);
            while (StrTok != NULL) {
                if (IsSubsystem(StrTok)) {
                    Result = TRUE;
                    break;
                }
                StrTok = strtok_r(NULL, ",", &Context);
            }
        } else if (CGroupVersion == 2) {
            //
            // See https://www.kernel.org/doc/Documentation/cgroup-v2.txt
            // Look for a "0::/some/path"
            //
            int SscanfRet = sscanf(Line, "0::%s", CGroupPath);
            if (SscanfRet == 1) {
                Result = TRUE;
            }
        } else {
            goto Done;
        }
    }

Done:

    free(SubsystemList);
    if (!Result) {
        free(CGroupPath);
        CGroupPath = NULL;
    }
    free(Line);
    if (CGroupFile) {
        fclose(CGroupFile);
    }
    return CGroupPath;
}

static
_Success_(return != NULL)
char*
FindCGroupPath(
    _In_ BOOLEAN (*IsSubsystem)(const char *)
    )
{
    char *CGroupPath = NULL;
    char *HierarchyMount = NULL;
    char *HierarchyRoot = NULL;
    char *CGroupPathRelativeToMount = NULL;
    size_t CommonPathPrefixLen;
    size_t CGroupPathLength;
    int PrintedLen;

    FindHierarchyMount(IsSubsystem, &HierarchyMount, &HierarchyRoot);
    if (HierarchyMount == NULL || HierarchyRoot == NULL) {
        goto Done;
    }

    CGroupPathRelativeToMount = FindCGroupPathForSubsystem(IsSubsystem);
    if (CGroupPathRelativeToMount == NULL) {
        goto Done;
    }

    CGroupPathLength = strlen(HierarchyMount) + strlen(CGroupPathRelativeToMount) + 1;
    CGroupPath = (char*)malloc(CGroupPathLength);
    if (CGroupPath == NULL) {
        goto Done;
    }

    //
    // For a host cgroup, we need to append the relative path.
    // The root and cgroup path can share a common prefix of the path that should not be appended.
    // Example 1 (docker):
    // hierarchy_mount:               /sys/fs/cgroup/cpu
    // hierarchy_root:                /docker/87ee2de57e51bc75175a4d2e81b71d162811b179d549d6601ed70b58cad83578
    // cgroup_path_relative_to_mount: /docker/87ee2de57e51bc75175a4d2e81b71d162811b179d549d6601ed70b58cad83578/my_named_cgroup
    // append do the cgroup_path:     /my_named_cgroup
    // final cgroup_path:             /sys/fs/cgroup/cpu/my_named_cgroup
    //
    // Example 2 (out of docker)
    // hierarchy_mount:               /sys/fs/cgroup/cpu
    // hierarchy_root:                /
    // cgroup_path_relative_to_mount: /my_named_cgroup
    // append do the cgroup_path:     /my_named_cgroup
    // final cgroup_path:             /sys/fs/cgroup/cpu/my_named_cgroup
    //
    CommonPathPrefixLen = strlen(HierarchyRoot);
    if ((CommonPathPrefixLen == 1) ||
        strncmp(
            HierarchyRoot,
            CGroupPathRelativeToMount,
            CommonPathPrefixLen) != 0) {
        CommonPathPrefixLen = 0;
    }

    CXPLAT_DBG_ASSERT(
        (CGroupPathRelativeToMount[CommonPathPrefixLen] == '/') ||
        (CGroupPathRelativeToMount[CommonPathPrefixLen] == '\0'));

    PrintedLen =
        snprintf(
            CGroupPath,
            CGroupPathLength,
            "%s%s",
            HierarchyMount,
            CGroupPathRelativeToMount + CommonPathPrefixLen);

    if (PrintedLen <= 0 || (size_t)PrintedLen >= CGroupPathLength) {
        //
        // Failed to copy. Free and return nothing.
        //
        free(CGroupPath);
        CGroupPath = NULL;
    }

Done:

    free(HierarchyMount);
    free(HierarchyRoot);
    free(CGroupPathRelativeToMount);
    return CGroupPath;
}

static
_Success_(return != FALSE)
BOOLEAN
GetCGroupMemoryLimit(
    _In_z_ const char *Filename,
    _Out_ uint64_t *MemValue)
{
    if (CGroupMemoryPath == NULL) {
        return FALSE;
    }

    char* MemLimitFilename = NULL;
    if (asprintf(&MemLimitFilename, "%s%s", CGroupMemoryPath, Filename) < 0) {
        return FALSE;
    }

    BOOLEAN Result = ReadMemoryValueFromFile(MemLimitFilename, MemValue);
    free(MemLimitFilename);
    return Result;
}

static
void
CGroupInitialize(
    void
    )
{
    CGroupVersion = FindCGroupVersion();
    CGroupMemoryPath = FindCGroupPath(CGroupVersion == 1 ? &IsCGroup1MemorySubsystem : NULL);
}

static
void
CGroupCleanup(
    void
    )
{
    free(CGroupMemoryPath);
}

static
_Success_(return != FALSE)
BOOLEAN
GetCGroupRestrictedMemoryLimit(
    _Out_ uint64_t* MemLimit
    )
{
    if (CGroupVersion == 1) {
        return GetCGroupMemoryLimit(CGROUP1_MEMORY_LIMIT_FILENAME, MemLimit);
    }
    if (CGroupVersion == 2) {
        return GetCGroupMemoryLimit(CGROUP2_MEMORY_LIMIT_FILENAME, MemLimit);
    }
    return FALSE;
}

static
uint64_t
GetPhysicalMemoryLimit(
    void
    )
{
#if HAS_SYSCONF && HAS__SC_PHYS_PAGES
    long Pages = sysconf(_SC_PHYS_PAGES);
    long PageSize = sysconf(_SC_PAGE_SIZE);
    if (Pages != -1 &&  PageSize != -1)
    {
        return Pages * PageSize;
    }
#elif HAS_SYSCTL
    int MIB[3];
    MIB[0] = CTL_HW;
    MIB[1] = HW_MEMSIZE;
    int64_t PhysicalMemory = 0;
    size_t MemLength = sizeof(int64_t);
    if (sysctl(MIB, 2, &PhysicalMemory, &MemLength, NULL, 0) == 0) {
        return PhysicalMemory;
    }
#endif
    return 0x40000000; // Hard coded at 1 GB if value unknown.
}

uint64_t
CGroupGetMemoryLimit()
{
    uint64_t PhysicalMemoryLimit = 0;
    uint64_t RestrictedMemoryLimit = 0;

    CGroupInitialize();

    PhysicalMemoryLimit = GetPhysicalMemoryLimit();

    if (!GetCGroupRestrictedMemoryLimit(&RestrictedMemoryLimit)) {
        goto Done;
    }

    //
    // If there's no memory limit specified on the container this
    // actually returns 0x7FFFFFFFFFFFF000 (2^63-1 rounded down to
    // 4k which is a common page size). So we know we are not
    // running in a memory restricted environment.
    //
    if (RestrictedMemoryLimit > 0x7FFFFFFF00000000) {
        goto Done;
    }

    struct rlimit CurrRlimit;
    size_t RlimitSoftLimit = (size_t)RLIM_INFINITY;
    if (getrlimit(RLIMIT_AS, &CurrRlimit) == 0) {
        RlimitSoftLimit = CurrRlimit.rlim_cur;
    }
    RestrictedMemoryLimit = (RestrictedMemoryLimit < RlimitSoftLimit) ?
                             RestrictedMemoryLimit : RlimitSoftLimit;

    //
    // Ensure that limit is not greater than real memory size
    //
    PhysicalMemoryLimit = (RestrictedMemoryLimit < PhysicalMemoryLimit) ?
                             RestrictedMemoryLimit : PhysicalMemoryLimit;

    if (PhysicalMemoryLimit > SIZE_T_MAX)
    {
        //
        // It is observed in practice when the memory is unrestricted, Linux control
        // group returns a physical limit that is bigger than the address space
        //
        PhysicalMemoryLimit = SIZE_T_MAX;
    }

Done:

    CGroupCleanup();

    if (PhysicalMemoryLimit == 0) {
        PhysicalMemoryLimit = 0x40000000; // Hard coded at 1 GB if value unknown.
    }

    return PhysicalMemoryLimit;
}
