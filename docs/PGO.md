# Profile Guided Optimizations

MsQuic uses [profile-guided optimizations](https://docs.microsoft.com/en-us/cpp/build/profile-guided-optimizations) (PGO) to generate optimized builds of the MsQuic library. PGO lets you optimize the whole library by using data from a previous run of the library.

> **Note** - This document is Windows specific.

# Build

During the build for x86 and x64 release builds (arm/arm64 are currently unsupported) a profile-guided database file (`.pgd`), generated from a previous run, is passed to the linker. The linker uses this data to optimize the new build.

## Build for Training

```
> ./scripts/build.ps1 -Config Release -PGO
```

By default, the library is not built in "training mode". To enable this, you must pass the `-PGO` switch to the `build.ps1` PowerShell script. This configures the linker to configure the library so that it can be trained. Whenever the library unloads a `.pgc` file will be dumped to the local directory. This file can be used update the existing `.pgd` file.

# Training

A fundamental part of profile-guided optimizations is training. The code is run through production scenarios while in "training mode" to generate a data set that can be used for a future build to optimize for the scenario.

1. [Build for training](#build-for-training).
2. Copy the binaries to the test machine(s).
   1. The PGO msquic library.
   2. The test tool (e.g. `quicping`).
   3. The PGO runtime library from your VS install: (e.g. `"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.26.28801\bin\Hostx64\x64\pgort140.dll"`).
3. Run the test for the production/performance scenario.
4. Use [pgomgr](https://docs.microsoft.com/en-us/cpp/build/pgomgr) to merge the `.pgc` into the `.pgd`.
5. Update the `.pgd` and `.pdb` files in the repository.
