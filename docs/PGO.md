# Profile Guided Optimizations

MsQuic uses [profile-guided optimizations](https://docs.microsoft.com/en-us/cpp/build/profile-guided-optimizations) (PGO) to generate optimized builds of the MsQuic library. PGO lets you optimize the whole library by using data from a previous run of the library.

> **Note**
> This document is Windows specific.

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
   2. The test tool (e.g. `secnetperf`).
   3. The PGO runtime library from your VS install: (e.g. `"C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.26.28801\bin\Hostx64\x64\pgort140.dll"`).
3. Run the test for the production/performance scenario.
4. Use [pgomgr](https://docs.microsoft.com/en-us/cpp/build/pgomgr) to merge the `.pgc` into the `.pgd`.
5. Update the `.pgd` and `.pdb` files in the repository.


# Kernel mode Profile Guided Optimizations

PGO for kernel mode is a much more manual process than user mode. These steps guide you through the process.

## Build

To build for kernel PGO, copy `pgortsys.lib` locally and edit the msquicpriv.kernel.vcxproj file with the following patch:

```patch
diff --git a/src/bin/winkernel/msquicpriv.kernel.vcxproj b/src/bin/winkernel/msquicpriv.kernel.vcxproj
index 04d89207..b125cdd7 100644
--- a/src/bin/winkernel/msquicpriv.kernel.vcxproj
+++ b/src/bin/winkernel/msquicpriv.kernel.vcxproj
@@ -78,7 +78,7 @@
   <ImportGroup Label="PropertySheets">
     <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
   </ImportGroup>
-  <PropertyGroup Label="UserMacros" />
+  <PropertyGroup><LibraryPath>$(LibraryPath);$(VC_LibraryPath_VC_x64_Desktop);c:\path\to\directory\containing\pgortsys.lib\</LibraryPath></PropertyGroup>
   <PropertyGroup>
     <QUIC_VER_BUILD_ID Condition="'$(QUIC_VER_BUILD_ID)' == ''">0</QUIC_VER_BUILD_ID>
     <QUIC_VER_SUFFIX Condition="'$(QUIC_VER_SUFFIX)' == ''">-private</QUIC_VER_SUFFIX>
@@ -106,7 +106,7 @@
     </ClCompile>
     <Link>
       <ModuleDefinitionFile>msquicpriv.src</ModuleDefinitionFile>
-      <AdditionalDependencies>cng.lib;ksecdd.lib;msnetioid.lib;ndis.lib;netio.lib;uuid.lib;%(AdditionalDependencies)</AdditionalDependencies>
+      <AdditionalDependencies>cng.lib;ksecdd.lib;msnetioid.lib;ndis.lib;netio.lib;uuid.lib;pgortsys.lib;%(AdditionalDependencies)</AdditionalDependencies>
       <AdditionalOptions>/kernel /NOOPTIDATA /pdbcompress /MERGE:.gfids=GFIDS /MERGE:.orpc=.text /MERGE:_PAGE=PAGE /MERGE:_RDATA=.rdata /MERGE:_TEXT=.text /section:GFIDS,d</AdditionalOptions>
       <LinkTimeCodeGeneration>UseLinkTimeCodeGeneration</LinkTimeCodeGeneration>
     </Link>
@@ -126,7 +126,7 @@
   </ItemDefinitionGroup>
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
     <Link>
-      <AdditionalOptions>%(AdditionalOptions) /FORCE:PGOREPRO /USEPROFILE:PGD=$(SolutionDir)artifacts\bin\winkernel\$(Platform)_$(Configuration)_schannel\priv\msquic.pgd</AdditionalOptions>
+      <AdditionalOptions>%(AdditionalOptions) /FORCE:PGOREPRO /LTCG:PGI /Profile</AdditionalOptions>
     </Link>
   </ItemDefinitionGroup>
   <ItemGroup>
```

You should **clean** build for x64 and Release.

Then build user mode MsQuic using the regular script with the following flags `-PGO -Tls schannel -config Release`.

## Setting up the perf machines

To train kernel mode PGO, we use the `secnetperf` utility.  To configure the perf machines, run the following powershell script as Administrator:
```ps1
param(
    # Build path
    [Parameter(Mandatory=$true)]
    [string]$BuildPath,

    # MsQuic location
    [Parameter(Mandatory=$true)]
    [string]$MsQuicPath,

    # CPU Architecture
    [Parameter(Mandatory=$false)]
    [ValidateSet("amd64", "x86", "arm", "arm64")]
    [string]$Arch="amd64"
)

$PgoBasePath = "$($BuildPath)\$($Arch)fre\pgo"

if (!(Test-Path -Path "c:\pgo_collection")) {
    New-Item -Path "c:\pgo_collection" -ItemType Directory -Force | Out-Null
}

Copy-Item -Path "$($PgoBasePath)\pgoapi\*" -Filter *.ps1 -Destination "C:\pgo_collection"
Copy-Item -Path "$($BuildPath)\$($Arch)fre\bin\idw\signTool.exe" -Destination "C:\pgo_collection"
Copy-Item -Path "$($BuildPath)\$($Arch)fre\bin\idw\signTool.dll" -Destination "C:\pgo_collection"

if (!(Test-Path -Path "c:\pgo_collection\sweep")) {
    New-Item -Path "c:\pgo_collection\sweep" -ItemType Directory -Force | Out-Null
}

Copy-Item -Path "$($PgoBasePath)\kmode\system32\pgosweep.exe"          -Destination "C:\pgo_collection\sweep"
Copy-Item -Path "$($PgoBasePath)\kmode\system32\vcruntime140.dll"      -Destination "C:\pgo_collection\sweep"
Copy-Item -Path "$($PgoBasePath)\kmode\system32\drivers\pgodriver.sys" -Destination "C:\pgo_collection\sweep"
Copy-Item -Path "$($PgoBasePath)\bbttools\bbtlddll.exe"                -Destination "C:\pgo_collection\sweep"
Copy-Item -Path "$($PgoBasePath)\bbttools\createdir.sys"               -Destination "C:\pgo_collection\sweep"
Copy-Item -Path "$($PgoBasePath)\tools\pgort140.dll"                   -Destination "C:\pgo_collection\sweep"

# Install PGO
powershell -NonInteractive -NoProfile -File "c:\pgo_collection\install-pgo.ps1" -PgoChunkPath $PgoBasePath -PgoChunkNativePath $PgoBasePath -PgoCollectionDir "c:\pgo_collection" -SignTool "c:\pgo_collection\signtool.exe" -PGOArch $Arch

# Fix PGODriver
sc.exe config pgodriver start= auto

# Copy MsQuic
if ($arch -eq "amd64") {
    $QuicArch = "x64"
} else {
    $QuicArch = $Arch
}

$WindowsBinPath = "artifacts\bin\windows\$($QuicArch)_Release_schannel"
$WinKernelBinPath = "artifacts\bin\winKernel\$($QuicArch)_Release_schannel"

if (!(Test-Path -Path "c:\msquic\$($WindowsBinPath)")) {
    New-Item -Path "c:\msquic\$($WindowsBinPath)" -ItemType Directory -Force | Out-Null
}

if (!(Test-Path -Path "c:\msquic\$($WinKernelBinPath)")) {
    New-Item -Path "c:\msquic\$($WinKernelBinPath)" -ItemType Directory -Force | Out-Null
}

Copy-Item -Path "$($MsQuicPath)\$($WindowsBinPath)\msquic.dll"   -Destination "c:\msquic\$($WinKernelBinPath)"
Copy-Item -Path "$($MsQuicPath)\$($WindowsBinPath)\secnetperf.exe" -Destination "c:\msquic\$($WinKernelBinPath)"
Copy-Item -Path "$($MsQuicPath)\$($WinKernelBinPath)\*"          -Destination "c:\msquic\$($WinKernelBinPath)"

sc.exe create "msquicpriv" type= kernel binpath= "C:\msquic\$($WinKernelBinPath)\msquicpriv.sys" start= demand

New-NetFirewallRule -DisplayName "Allow SecNetPerf" -Enabled True -Profile Any -Direction Inbound -Action Allow -Protocol UDP -LocalPort 4433

bcdedit /debug on

Write-Host Now Reboot the machine
```
Make sure the machine is configured for kernel debugging and a kernel debugger is attached, otherwise the msquicpriv.sys driver won't load.

## Training

Now that the perf machines are configured for kernel mode PGO, it's time to run the scenarios.

On the machine that will act as server, run the following command to start the server:
```
secnetperf.exe -kernel
```

Once running, clear the PGO counts on both the client and server machines to get a clean slate:

```
pgosweep.exe /driver msquicpriv.sys .\msquicpriv.pgc
del msquicpriv.pgc
```

On the machine acting as client, run the following commands to generate traffic:
```
secnetperf.exe --kernel -test:tput -target:<server IP> -upload:5000000000
secnetperf.exe --kernel -test:tput -target:<server IP> -download:5000000000
secnetperf.exe --kernel -test:RPS -target:<server IP>
secnetperf.exe --kernel -test:HPS -target:<server IP>
```

After the client finishes all scenarios, run this again on the client and the server to collect the updated counts:
```
pgosweep.exe /driver msquicpriv.sys .\msquicpriv.pgc
```

Copy the .pgc files to a machine with the Visual Studio tools installed and run the following to merge
the PGC files into the PGD that was generated during build, and then copy that PGD into the git repo:
```
pgomgr.exe /merge msquicpriv-client.pgc msquicpriv-server.pgc c:\msquic\artifacts\bin\winkernel\x64_Release_schannel\msquicpriv.pgd
xcopy :\msquic\artifacts\bin\winkernel\x64_Release_schannel\msquicpriv.pgd c:\msquic\src\bin\winkernel\pgo_x64\msquic.pgd
```

If `pgomgr.exe` emits a warning that the database doesn't match, use `pgodump.exe` to check the ID of both the
PGD and PGC files and ensure they match. If the PGC file doesn't match, it's most likely because `msquicpriv.sys`
didn't unload completely when you installed a new one.  You will need to stop `PGODriver.sys` before stopping
`msquicpriv.sys` when replacing `msquicpriv.sys` with a newer version.  You can also reboot the system after
replacing `msquicpriv.sys`.

Sample output from `pgodump.exe` showing the IDs are same between PGD and PGC
```
> pgodump.exe c:\msquic\artifacts\bin\winkernel\x64_Release_schannel\msquicpriv.pgd
Microsoft (R) Profile Guided Optimization Database Dump Utility
Copyright (C) Microsoft Corporation. All rights reserved.

PGD File: c:\msquic\artifacts\bin\winkernel\x64_Release_schannel\msquicpriv.pgd (v44, ID CC21BC03, Signature 4F474F50)  10/27/2020 22:25:53
```
```
> pgodump.exe msquicpriv-client.pgc
Microsoft (R) Profile Guided Optimization Database Dump Utility
Copyright (C) Microsoft Corporation. All rights reserved.

PGC File: msquicpriv!client.pgc (ID CC21BC03)
```
