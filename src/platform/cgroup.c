// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*++

Module Name:

    cgroup.cpp

Abstract:
    Read the memory limit for the current process
--*/
#ifdef __FreeBSD__
#define _WITH_GETLINE
#endif

#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/param.h>
#include <sys/mount.h>
#else
#include <sys/vfs.h>
#endif
#include <errno.h>
#include "quic_platform.h"

#ifndef SIZE_T_MAX
#define SIZE_T_MAX (~(size_t)0)
#endif

#define CGROUP2_SUPER_MAGIC 0x63677270
#define TMPFS_MAGIC 0x01021994

#define PROC_MOUNTINFO_FILENAME "/proc/self/mountinfo"
#define PROC_CGROUP_FILENAME "/proc/self/cgroup"
#define PROC_STATM_FILENAME "/proc/self/statm"
#define CGROUP1_MEMORY_LIMIT_FILENAME "/memory.limit_in_bytes"
#define CGROUP2_MEMORY_LIMIT_FILENAME "/memory.max"
#define CGROUP_MEMORY_STAT_FILENAME "/memory.stat"

// Get memory size multiplier based on the passed in units (k = kilo, m = mega, g = giga)
static uint64_t GetMemorySizeMultiplier(char units)
{
    switch(units)
    {
        case 'g':
        case 'G': return 1024 * 1024 * 1024;
        case 'm':
        case 'M': return 1024 * 1024;
        case 'k':
        case 'K': return 1024;
    }

    // No units multiplier
    return 1;
}

static
BOOLEAN
ReadMemoryValueFromFile(const char* filename, uint64_t* val)
{
    bool result = false;
    char *line = NULL;
    size_t lineLen = 0;
    char* endptr = NULL;
    uint64_t num = 0, multiplier;

    if (val == NULL)
        return false;

    FILE* file = fopen(filename, "r");
    if (file == NULL)
        goto done;

    if (getline(&line, &lineLen, file) == -1)
        goto done;

    errno = 0;
    num = strtoull(line, &endptr, 0);
    if (errno != 0)
        goto done;

    multiplier = GetMemorySizeMultiplier(*endptr);
    *val = num * multiplier;
    result = true;
    if (*val/multiplier != num)
        result = false;
done:
    if (file)
        fclose(file);
    free(line);
    return result;
}

static int CGroupVersion = 0;
static char* CGroupMemoryPath = NULL;
static const char* CGroupMemStatKeyNames[4];
static size_t CGroupMemStatKeyLengths[4];
static size_t CGroupMemStatNKeys = 0;

static BOOLEAN CGroupIsCGroup1MemorySubsystem(const char *strTok){
    return strcmp("memory", strTok) == 0;
}

static int CGroupFindCGroupVersion() {
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
        default:
            CXPLAT_DBG_ASSERTMSG(FALSE, "Unexpected file system type for /sys/fs/cgroup");
            return 0;
    }
}

    static void FindHierarchyMount(BOOLEAN (*is_subsystem)(const char *), char** pmountpath, char** pmountroot)
    {
        char *line = NULL;
        size_t lineLen = 0, maxLineLen = 0;
        char *filesystemType = NULL;
        char *options = NULL;
        char *mountpath = NULL;
        char *mountroot = NULL;

        FILE *mountinfofile = fopen(PROC_MOUNTINFO_FILENAME, "r");
        if (mountinfofile == NULL)
            goto done;

        while (getline(&line, &lineLen, mountinfofile) != -1)
        {
            if (filesystemType == NULL || lineLen > maxLineLen)
            {
                free(filesystemType);
                filesystemType = NULL;
                free(options);
                options = NULL;
                filesystemType = (char*)malloc(lineLen+1);
                if (filesystemType == NULL)
                    goto done;
                options = (char*)malloc(lineLen+1);
                if (options == NULL)
                    goto done;
                maxLineLen = lineLen;
            }

            char* separatorChar = strstr(line, " - ");

            // See man page of proc to get format for /proc/self/mountinfo file
            int sscanfRet = sscanf(separatorChar,
                                   " - %s %*s %s",
                                   filesystemType,
                                   options);
            if (sscanfRet != 2)
            {
                CXPLAT_DBG_ASSERTMSG(FALSE, "Failed to parse mount info file contents with sscanf.");
                goto done;
            }

            if (strncmp(filesystemType, "cgroup", 6) == 0)
            {
                bool isSubsystemMatch = is_subsystem == NULL;
                if (!isSubsystemMatch)
                {
                    char* context = NULL;
                    char* strTok = strtok_r(options, ",", &context);
                    while (!isSubsystemMatch && strTok != NULL)
                    {
                        isSubsystemMatch = is_subsystem(strTok);
                        strTok = strtok_r(NULL, ",", &context);
                    }
                }
                if (isSubsystemMatch)
                {
                        mountpath = (char*)malloc(lineLen+1);
                        if (mountpath == NULL)
                            goto done;
                        mountroot = (char*)malloc(lineLen+1);
                        if (mountroot == NULL)
                            goto done;

                        sscanfRet = sscanf(line,
                                           "%*s %*s %*s %s %s ",
                                           mountroot,
                                           mountpath);
                        if (sscanfRet != 2) {
                            CXPLAT_DBG_ASSERTMSG(FALSE, "Failed to parse mount info file contents with sscanf.");
                        }

                        // assign the output arguments and clear the locals so we don't free them.
                        *pmountpath = mountpath;
                        *pmountroot = mountroot;
                        mountpath = mountroot = NULL;
                }
            }
        }
    done:
        free(mountpath);
        free(mountroot);
        free(filesystemType);
        free(options);
        free(line);
        if (mountinfofile) {
            fclose(mountinfofile);
        }
    }

    static char* FindCGroupPathForSubsystem(BOOLEAN (*is_subsystem)(const char *))
    {
        char *line = NULL;
        size_t lineLen = 0;
        size_t maxLineLen = 0;
        char *subsystem_list = NULL;
        char *cgroup_path = NULL;
        bool result = false;

        FILE *cgroupfile = fopen(PROC_CGROUP_FILENAME, "r");
        if (cgroupfile == NULL)
            goto done;

        while (!result && getline(&line, &lineLen, cgroupfile) != -1)
        {
            if (subsystem_list == NULL || lineLen > maxLineLen)
            {
                free(subsystem_list);
                subsystem_list = NULL;
                free(cgroup_path);
                cgroup_path = NULL;
                subsystem_list = (char*)malloc(lineLen+1);
                if (subsystem_list == NULL)
                    goto done;
                cgroup_path = (char*)malloc(lineLen+1);
                if (cgroup_path == NULL)
                    goto done;
                maxLineLen = lineLen;
            }

            if (CGroupVersion == 1)
            {
                // See man page of proc to get format for /proc/self/cgroup file
                int sscanfRet = sscanf(line,
                                       "%*[^:]:%[^:]:%s",
                                       subsystem_list,
                                       cgroup_path);
                if (sscanfRet != 2)
                {
                    assert(!"Failed to parse cgroup info file contents with sscanf.");
                    goto done;
                }

                char* context = NULL;
                char* strTok = strtok_r(subsystem_list, ",", &context);
                while (strTok != NULL)
                {
                    if (is_subsystem(strTok))
                    {
                        result = true;
                        break;
                    }
                    strTok = strtok_r(NULL, ",", &context);
                }
            }
            else if (CGroupVersion == 2)
            {
                // See https://www.kernel.org/doc/Documentation/cgroup-v2.txt
                // Look for a "0::/some/path"
                int sscanfRet = sscanf(line,
                                       "0::%s",
                                       cgroup_path);
                if (sscanfRet == 1)
                {
                    result = true;
                }
            }
            else
            {
                assert(!"Unknown cgroup version in mountinfo.");
                goto done;
            }
        }
    done:
        free(subsystem_list);
        if (!result)
        {
            free(cgroup_path);
            cgroup_path = NULL;
        }
        free(line);
        if (cgroupfile)
            fclose(cgroupfile);
        return cgroup_path;
    }

static char* FindCGroupPath(BOOLEAN (*is_subsystem)(const char *)){
    char *cgroup_path = NULL;
    char *hierarchy_mount = NULL;
    char *hierarchy_root = NULL;
    char *cgroup_path_relative_to_mount = NULL;
    size_t common_path_prefix_len;

    FindHierarchyMount(is_subsystem, &hierarchy_mount, &hierarchy_root);
    if (hierarchy_mount == NULL || hierarchy_root == NULL)
        goto done;

    cgroup_path_relative_to_mount = FindCGroupPathForSubsystem(is_subsystem);
    if (cgroup_path_relative_to_mount == NULL)
        goto done;

    cgroup_path = (char*)malloc(strlen(hierarchy_mount) + strlen(cgroup_path_relative_to_mount) + 1);
    if (cgroup_path == NULL) {
        goto done;
    }

    strcpy(cgroup_path, hierarchy_mount);
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
    common_path_prefix_len = strlen(hierarchy_root);
    if ((common_path_prefix_len == 1) || strncmp(hierarchy_root, cgroup_path_relative_to_mount, common_path_prefix_len) != 0)
    {
        common_path_prefix_len = 0;
    }

    CXPLAT_DBG_ASSERT((cgroup_path_relative_to_mount[common_path_prefix_len] == '/') || (cgroup_path_relative_to_mount[common_path_prefix_len] == '\0'));

    strcat(cgroup_path, cgroup_path_relative_to_mount + common_path_prefix_len);


done:
    free(hierarchy_mount);
    free(hierarchy_root);
    free(cgroup_path_relative_to_mount);
    return cgroup_path;
}

    static bool GetCGroupMemoryLimit(uint64_t *val, const char *filename)
    {
        if (CGroupMemoryPath == NULL)
            return false;

        char* mem_limit_filename = NULL;
        if (asprintf(&mem_limit_filename, "%s%s", CGroupMemoryPath, filename) < 0)
            return false;

        bool result = ReadMemoryValueFromFile(mem_limit_filename, val);
        free(mem_limit_filename);
        return result;
    }

static void CGroupInitialize() {
    CGroupVersion = CGroupFindCGroupVersion();
    CGroupMemoryPath = FindCGroupPath(CGroupVersion == 1 ? &CGroupIsCGroup1MemorySubsystem : NULL);

    if (CGroupVersion == 1) {
        CGroupMemStatNKeys = 4;
        CGroupMemStatKeyNames[0] = "total_inactive_anon ";
        CGroupMemStatKeyNames[1] = "total_active_anon ";
        CGroupMemStatKeyNames[2] = "total_dirty ";
        CGroupMemStatKeyNames[3] = "total_unevictable ";
    } else {
        CGroupMemStatNKeys = 3;
        CGroupMemStatKeyNames[0] = "anon ";
        CGroupMemStatKeyNames[1] = "file_dirty ";
        CGroupMemStatKeyNames[2] = "unevictable ";
    }

    for (size_t i = 0; i < CGroupMemStatNKeys; i++) {
        CGroupMemStatKeyLengths[i] = strlen(CGroupMemStatKeyNames[i]);
    }
}

static void CGroupCleanup() {
    free(CGroupMemoryPath);
}

static BOOLEAN CGroupGetPhysicalMemoryLimit(_Out_ uint64_t* MemLimit) {
    if (CGroupVersion == 0) {
        return FALSE;
    } else if (CGroupVersion == 1) {
        return GetCGroupMemoryLimit(MemLimit, CGROUP1_MEMORY_LIMIT_FILENAME);
    } else if (CGroupVersion == 2) {
        return GetCGroupMemoryLimit(MemLimit, CGROUP2_MEMORY_LIMIT_FILENAME);
    } else {
        CXPLAT_DBG_ASSERTMSG(FALSE, "Unknown cgroup version");
        return FALSE;
    }
}

void CGroupInitializeCGroup() {
    CGroupInitialize();
}

void CGroupCleanupCGroup() {
    CGroupCleanup();
}

size_t CGroupGetRestrictedPhysicalMemoryLimit()
{
    uint64_t physical_memory_limit = 0;

    if (!CGroupGetPhysicalMemoryLimit(&physical_memory_limit))
         return 0;

    // If there's no memory limit specified on the container this
    // actually returns 0x7FFFFFFFFFFFF000 (2^63-1 rounded down to
    // 4k which is a common page size). So we know we are not
    // running in a memory restricted environment.
    if (physical_memory_limit > 0x7FFFFFFF00000000)
    {
        return 0;
    }

    struct rlimit curr_rlimit;
    size_t rlimit_soft_limit = (size_t)RLIM_INFINITY;
    if (getrlimit(RLIMIT_AS, &curr_rlimit) == 0)
    {
        rlimit_soft_limit = curr_rlimit.rlim_cur;
    }
    physical_memory_limit = (physical_memory_limit < rlimit_soft_limit) ?
                            physical_memory_limit : rlimit_soft_limit;

    // Ensure that limit is not greater than real memory size
    long pages = sysconf(_SC_PHYS_PAGES);
    if (pages != -1)
    {
        long pageSize = sysconf(_SC_PAGE_SIZE);
        if (pageSize != -1)
        {
            physical_memory_limit = (physical_memory_limit < (size_t)pages * pageSize)?
                                    physical_memory_limit : (size_t)pages * pageSize;
        }
    }

    if (physical_memory_limit > SIZE_T_MAX)
    {
        // It is observed in practice when the memory is unrestricted, Linux control
        // group returns a physical limit that is bigger than the address space
        return SIZE_T_MAX;
    }
    else
    {
        return (size_t)physical_memory_limit;
    }
}
