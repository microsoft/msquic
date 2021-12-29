::
::  Copyright (C) Microsoft. All rights reserved.
::
::  THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
::  ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
::  IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
::  PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
::

@echo off
setlocal enabledelayedexpansion

@rem vars
set disp=
set exe=
set mode=
set tool=
set etl=
set evtx=
set bins=

@rem directories and files
set statedir=
set servicefile=
set taskfile=

@rem cli-srv shared logs
set rpcxdr=0
set sec=0
set tcp=0

@rem parsed args - on
set single=0
set capture=0
set cli=0
set srv=0
set brief=
set verbose=
set ca=
set csv=0
set hyperv=0
set cluster=0
set circ=
set circbuf=
set circargs=
set level=2
set rdbss=
set rdbssflags=
set rdbsslevel=
set mrxsmb=
set mrxsmbflags=
set mrxsmblevel=
set smb20=
set smb20flags=
set smb20level=
set quic=0

@rem parsed args - off
set nobin=
set nocab=

@rem bin groups for the defined streams
set dfsn_bins=dfssvc.exe dfs.sys
set dns_bins=dnsapi.dll dnsrslvr.dll
set fr_bins=fde.dll fdeploy.dll shell32.dll
set fskm_bins=cscobj.dll cscsvc.dll csc.sys dfsc.sys mup.sys mrxsmb10.sys mrxsmb20.sys mrxsmb.sys mrxdav.sys nfsrdr.sys rdbss.sys ccffilter.sys resumekeyfilter.sys peerdist.dll peerdistsvc.dll peerdistsh.dll wkssvc.dll wvrf.sys
set fsum_bins=cscapi.dll cscui.dll davclnt.dll davhlpr.dll webclnt.dll
set nbt_bins=netbt.sys smb.sys
set nfs_bins=msnfsflt.sys nfssvr.sys portmap.sys
set rpcxdr_bins=rpcxdr.sys
set sec_bins=kerberos.dll msv1_0.dll negoexts.dll pku2u.dll
set smbhash_bins=hashgen.exe smbgproxy.dll smbhash.exe peerdisthash.dll peerdistsh.dll
set srv_bins=srv.sys srv2.sys srvnet.sys srvsvc.dll witness.exe
set tcp_bins=tcpip.sys
set quic_bins=msquic.sys
set csvfs_bins=csvfs.sys
set csvflt_bins=csvflt.sys
set csvvbus_bins=csvvbus.sys vbus.sys
set csvnflt_bins=csvnflt.sys nflt.sys
set sr_bins=wvrf.sys

call :persistGet statedir statedir
call :detectMode %*
if errorlevel 1 (
    echo.ERROR: operation mode must be specified
    echo.
    call :usage
    exit /b 1
)

call :getCoreOnly %*
if errorlevel 1 set level=1

if /i "%mode%" equ "on" goto :nextonarg
if /i "%mode%" equ "snapshot" goto :nextsnapshotarg
@rem if /i "%mode%" equ "off" goto :nextoffarg

:nextoffarg
if           "%~1" equ ""        ( goto :offargfini
) else if /i "%~1" equ "off"     ( echo.>NUL
) else if /i "%~1" equ "clioff"  ( echo.>NUL
) else if /i "%~1" equ "srvoff"  ( echo.>NUL
) else if /i "%~1" equ "nocab"   ( set nocab=1
) else if /i "%~1" equ "nobin"   ( set nobin=1
) else (
        call :invalid %1
        @rem tracing still running; don't clear persistant state
        exit /b 1
)
shift /1
goto :nextoffarg

:nextsnapshotarg
if           "%~1" equ ""           ( goto :offargfini
) else if /i "%~1" equ "snapshot"   ( echo.>NUL
) else if /i "%~1" equ "nocab"      ( set nocab=1
) else if /i "%~1" equ "nobin"      ( set nobin=1
) else (
        call :invalid %1
        @rem tracing still running; don't clear persistant state
        exit /b 1
)
shift /1
goto :nextsnapshotarg

:nextonarg
if           "%~1" equ ""        ( goto :onargfini
) else if /i "%~1" equ "capture" ( set capture=1
) else if /i "%~1" equ "clion"   ( set cli=%level%
) else if /i "%~1" equ "srvon"   ( set srv=%level%
) else if /i "%~1" equ "brief"   ( set brief=1
) else if /i "%~1" equ "verbose" ( set verbose=1
) else if /i "%~1" equ "ca"      ( set ca=1
) else if /i "%~1" equ "core"    ( @rem no-op
) else if /i "%~1" equ "csv"     ( set csv=1
) else if /i "%~1" equ "single"  ( set single=1
) else if /i "%~1" equ "hyperv"  ( set hyperv=1
) else if /i "%~1" equ "cluster" ( set cluster=1
) else if /i "%~1" equ "quic" ( set quic=1
) else (
        call :checkcirc %1
        if errorlevel 1 (
            call :checkdriver %1
            if errorlevel 1 (
                    call :invalid %1
                    @rem clear state
                    goto :off_final
            )
       )
)
shift /1
goto :nextonarg

:offargfini
if "%statedir%" equ "" (
    echo.ERROR: no tracing session in progress
    echo.
    call :usage
    exit /b 1
)
goto :argsfini

:onargfini
if "%statedir%" neq "" (
    echo.ERROR: tracing session already in progress.
    echo. Stop the existing tracing session before starting another.
    call :usage
    exit /b 1
)
if %cluster% equ 0 set cluster=%csv%

call :mkstatedir "%TEMP%\t"
call :dopersist statedir
goto :argsfini

:argsfini
:: #########################
:: Store/Recover persisted state for binary inclusion at stop time
:: #########################
call :dopersist single
call :dopersist capture
call :dopersist cli
call :dopersist srv
call :dopersist csv
call :dopersist circ
call :dopersist circbuf
call :dopersist hyperv
call :dopersist cluster
call :dopersist verbose
call :dopersist rdbss
call :dopersist rdbssflags
call :dopersist rdbsslevel
call :dopersist mrxsmb
call :dopersist mrxsmbflags
call :dopersist mrxsmblevel
call :dopersist smb20
call :dopersist smb20flags
call :dopersist smb20level
call :dopersist quic

@rem common components enabled by both cli and srv options
if %cli% gtr 0 set rpcxdr=1
if %srv% gtr 0 set rpcxdr=1
if %cli% gtr 1 set sec=1
if %srv% gtr 1 set sec=1
if %cli% gtr 1 set tcp=1

@rem enable sec, wfp-tcp traces for Hyper-V servers even with 'core' specified
if %cli% gtr 0 if %csv% equ 0 (
        set sec=1
        set tcp=1
)

:: #########################
:: OS-specific checks...
:: #########################

for /f "tokens=2 delims=[]" %%i in ('ver')    do @set OSVERTEMP=%%i
for /f "tokens=2" %%i in ('echo %OSVERTEMP%') do @set OSVER=%%i
for /f "tokens=1 delims=." %%i in ('echo %OSVER%') do @set OSVER1=%%i
for /f "tokens=2 delims=." %%i in ('echo %OSVER%') do @set OSVER2=%%i
for /f "tokens=3 delims=." %%i in ('echo %OSVER%') do @set OSVER3=%%i

:: #########################
::Detect Vista/LH OS Versions
:: #########################
set HasNDISCap=

if %OSVER1% equ 5 (
        goto :knownos
) else if %OSVER1% equ 6 (
        if %OSVER2% geq 1 set HasNDISCap=1
        if %OSVER2% geq 2 set nobin=1

        if %OSVER2% leq 3 goto :knownos
        goto :unknownos
) else if %OSVER1% equ 10 (
        set HasNDISCap=1
        set nobin=1
        if %OSVER3% equ 10240 goto :knownos
        if %OSVER3% equ 10586 goto :knownos
        if %OSVER3% equ 14393 goto :knownos
        goto :unknownos
) else (
        @rem Win9x, Win ME, NT 3-4
        echo. ERROR: Unsupported OS version [%OSVER%]
        exit /b 1
)

:unknownos
echo. WARNING : Unknown OS version [%OSVER%]
echo.

:knownos

::
:: Check if NetSH has the trace context installed,
:: which signifies ndiscap support.
:: (Win7 build of WinPE does not)
::
netsh trace >NUL 2>&1
if errorlevel 1 (
       set HasNDISCap=
)

if %capture% gtr 0 (
        if not defined HasNDISCap (
            set capture=0
            echo. Packet capture is only supported on Windows 7 / 2008 R2
            echo. or newer operating systems.
            echo.
            call :invalid capture
            exit /b 1
        )
        for %%i in (sc.exe) do (set exe=%%~$PATH:i)
        if "!exe!" equ "" (
            set capture=0
            echo. Packet capture requires sc.exe to be present in order
            echo. to start the filter driver.
            call :invalid capture
            exit /b 1
        )
)

:: ###################################
:: Check for local Admin rights, and prompt for elevation as needed
:: ###################################

call :mktemp _lua_filename %systemdrive%\lua dat
set _lua_running=false
@rem redirect 'Access Denied' error from cmd (not echo) to NUL
(echo 1>%_lua_filename%) >NUL 2>&1
if exist %_lua_filename% (
        set _lua_running=true
        del /q %_lua_filename%
)
if '%_lua_running%' equ 'false' (
        echo. ERROR: This script requires administrator access.
        echo.
        echo. Please relaunch the command prompt with administrator privileges.
        call :persistDelete
        exit /b 1
)

if /i "%mode%" neq "on" goto :skiponchecks
set /a optionsum=cli+srv
if %optionsum% equ 0 (
        echo.ERROR: At least one of the clion or srvon options must
        echo. be specified in order to enable tracing.
        call :persistDelete
        call :usage
        exit /b 1
)

:skiponchecks
set tool=
call :toolsearch logman.exe
if "!tool!" equ "" (
        call :toolsearch tracelog.exe
)
if "!tool!" equ "" (
        echo. No available programs available to enable tracing.
        echo. One of the following must be located in a directory in the PATH:
        echo.     logman.exe
        echo.     tracelog.exe
        call :persistDelete
        exit /b 1
)

if defined USERDOMAIN (
        set NdisCapTraceSession=NetTrace-%USERDOMAIN%-%USERNAME%
) else (
        set NdisCapTraceSession=NetTrace-%USERNAME%
)

set SingleTraceFile=trace
set NdisCapTraceFile=packetcapture
if %single% geq 1 set NdisCapTraceFile=%SingleTraceFile%

:snapshot-restart
set servicefile=%statedir%\services.txt
set taskfile=%statedir%\tasklist.txt

if /i "%mode%" neq "on" goto :core
@rem initialization prior to enabling traces (includes packet capture)

@rem grab the current process list before turning on tracing
@rem and be resilient to the absence of tasklist.exe
for %%i in (tasklist.exe) do (set exe=%%~$PATH:i)
if "!exe!" equ "" (
        echo tasklist.exe is not present > !taskfile!
) else (
        !exe! /FO csv /svc > !taskfile!
)

@rem grab the current service list as well
for %%i in (sc.exe) do (set exe=%%~$PATH:i)
if "!exe!" equ "" (
        echo sc.exe is not present > !servicefile!
) else (
        !exe! query type= all state= all > !servicefile!
)

if %capture% geq 1 goto :captureon
if %single% geq 1 goto :singleon
goto :core

:captureon
set netshmode=fileMode=single
if defined circ set circargs=maxSize=%circbuf% fileMode=circular
call :doit netsh trace start capture=yes traceFile="%statedir%\%NdisCapTraceFile%.etl" %circargs% correlation=no
set circargs=
if not errorlevel 1 ( set disp=started %NdisCapTraceFile% ^<- ndiscap )
if %single% equ 0 call :disp
goto :core

:singleon
call :traceon-%tool% %NdisCapTraceSession% %SingleTraceFile%
if not errorlevel 1 ( set disp=started trace ^<- )
goto :core

:core
if %cli% gtr 0 (
        call :doetl fskm
        call :doetl fsum

        if %cli% gtr 1 (
                call :doetl dns
                call :doetl fr
                call :doetl nbt
        )
)

if %srv% gtr 0 (
        call :doetl dfsn
        call :doetl srv
        call :doetl smbhash
        call :doetl nfs
        call :doetl sr
)

if %rpcxdr% gtr 0 (
        call :doetl rpcxdr
)

if %sec% gtr 0 (
        @rem enabled by either cli or srv
        call :doetl sec
)

if %tcp% gtr 0 (
        call :doetl tcp
)

if %quic% gtr 0 (
	call :doetl quic
)

if %csv% gtr 0 (
        call :doetl csvfs
        call :doetl csvflt
        call :doetl csvvbus
        call :doetl csvnflt
)

call :doevtlog

if /i "%mode%" equ "on" goto :on_final

@rem packet capture must be the last to stop

if %capture% geq 1 goto :captureoff
if %single% geq 1 goto :singleoff
goto :off

:captureoff
echo.Please be patient as NetSH retrieves the packet captures...
echo.This will take a few minutes.
call :doit netsh trace stop
set etl=!etl! %NdisCapTraceFile%.etl
@rem remove netsh report that can't be turned off
call :doit del %statedir%\%NdisCapTraceFile%.cab
goto :off

:singleoff
call :traceoff-%tool% %NdisCapTraceSession%
set etl=%SingleTraceFile%.etl
call :disp
goto :off

:invalid
echo.
echo. invalid parameter: %1
echo.
@rem fall through to usage

:usage
echo. Enabling Tracing:
echo.     usage: %~n0 [clion] [srvon] [core] [verbose] [capture] [csv] [cluster] [hyperv] [circ:N] [driver:flags:level]
echo.     clion   - generate client component traces
echo.     srvon   - generate server component traces
echo.     capture - enable packet capture ^(Windows 7 / Windows 2008 R2 or newer^)
echo.
echo.         At least one of cli, srv, and capture must
echo.         be specified.
echo.
echo.     csv     - generate CSV component traces
echo.     cluster - collect Cluster event logs
echo.     hyperv  - collect Hyper-V event logs
echo.     verbose - verbose mode tracing flags (defined for fskm/mup)
echo.     circ:N  - generate circular logs of size N megabytes
echo.               (default circular buffer size is 50 MB per log)
echo.     driver:flags:level - specify trace flags and level for this driver (support rdbss, mrxsmb, smb20 only)
echo.                          flags and level must be in hex
echo.         rdbss:  0x0001 error     0x0002 misc     0x0004 io        0x0008 openclose
echo.                 0x0010 readwrite 0x0020 fileinfo 0x0040 oplock    0x0080 connectionobject
echo.                 0x0100 fcb       0x0200 caching  0x0400 migration 0x0800 namecache
echo.                 0x1000 security
echo.         mrxsmb: 0x0001 error     0x0002 misc        0x0004 network          0x0008 security
echo.                 0x0010 exchange  0x0020 compounding 0x0040 connectionobject 0x0080 midwindow
echo.                 0x0100 multichannel
echo.         smb20:  0x0001 error    0x0002 misc   0x0004 network 0x0008 security
echo.                 0x0010 exchange 0x0020 io     0x0040 handle  0x0080 infocache
echo.                 0x0100 dircache 0x0200 oplock
echo.         level:  0x1 error 0x2 brief 0x4 verbose
echo. Disabling Tracing:
echo. usage: %~n0 off [nocab] [nobin]
echo.     off     - turn off tracing
echo.     nocab   - do not compress traces
echo.     nobin   - do not gather system binaries matching the captured traces
echo.               (please do not use if external to FSF/without direction)
echo.
echo. Disabling/Enabling Tracing:
echo. usage: %~n0 snapshot [nocab] [nobin]
goto :eof

@@@@@@@@@
@
@ tracing steps:
@
@ 1. tracepre: setup required prior to listing streams
@ 2. traceadd: add a stream to the session
@ 3. tracepost: final setup after mentioning all streams
@ 4. disp: dump rendering of what trace* did
@

:doetl
if %mode% equ on (
        call :traceon %1
        call :%1on
        if %single% equ 0 call :disp
) else (
        if %single% equ 0 (
            call :traceoff %1
            set etl=!etl! %1.etl
        )
        @rem roll up the binaries associated with this trace, if specified
        if not defined nobin set bins=!bins! !%1_bins!
)
goto :eof

:doevtlog
if %mode% equ on  goto :doevtlogon
if %mode% neq on goto :doevtlogoff
:goto :eof

:doevtlogon
goto :eof

:doevtlogoff
if %cli% gtr 0 (
        @rem SMB Client
        call :export-evtx Microsoft-Windows-SMBClient/Connectivity
        call :export-evtx Microsoft-Windows-SMBClient/Operational
        if %OSVER1% lss 10 call :export-evtx WitnessClientAdmin Witness-Admin.evtx
        if %OSVER1% geq 10 call :export-evtx Microsoft-Windows-SMBWitnessClient/Admin Witness-Admin.evtx
)

if %cluster% gtr 0 (
        @rem Cluster Nodes (Admin, Diagnostic, Operational channels)
        call :export-evtx System
        call :export-evtx Microsoft-Windows-FailoverClustering/Diagnostic
        call :export-evtx Microsoft-Windows-FailoverClustering/Operational
)

if %hyperv% gtr 0 (
        @rem Hyper-V Events
        call :export-evtx Microsoft-Windows-Hyper-V-VMMS-Admin
)
if defined evtx echo.evtlog -^> %evtx%
goto :eof

:export-evtx
set "channel=%~1"
set "file=%~2"
if "%file%" equ "" set "file=%channel:/=-%.evtx"
if /i "%file:~0,18%" equ "Microsoft-Windows-" set "file=%file:~18%"
wevtutil epl "%channel%" "%statedir%\%file%" "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" >NUL 2>NUL
if %ERRORLEVEL% equ 0 set "evtx=!evtx! %file%"
exit /b

@@@@@@@@
:fskmon

if %OSVER1% lss 10 (
    if defined verbose (
        set flags=0xfffffff
    ) else (
        set flags=0x3333333
    )
    set level=7

    call :traceadd fskm     20c46239-d059-4214-a11e-7d6769cbe020 csckm/dav/dfsc/mup/rdbss/smb !level! !flags!
) else (

    if not defined ca (
        if defined verbose (
            set flags=0xffff0f0
            set level=7
        ) else (
            set flags=0x3333030
            set level=0
        )

        call :traceadd fskm     20c46239-d059-4214-a11e-7d6769cbe020 csckm/dav/dfsc/mup !level! !flags!
    )

    if defined verbose (
        set level=4
    ) else (
        set level=2
    )

    set flags=0xffffffff

    if defined ca (
        set flags=0x5
    )

    if defined rdbss (
        call :traceadd fskm     0086eae4-652e-4dc7-b58f-11fa44f927b4 rdbss !rdbsslevel! !rdbssflags!
    ) else (
        call :traceadd fskm     0086eae4-652e-4dc7-b58f-11fa44f927b4 rdbss !level! !flags!
    )

    if defined ca (
        set flags=0x75
    )

    if defined mrxsmb (
        call :traceadd fskm     f818ebb3-fbc4-4191-96d6-4e5c37c8a237 mrxsmb !mrxsmblevel! !mrxsmbflags!
    ) else (
        call :traceadd fskm     f818ebb3-fbc4-4191-96d6-4e5c37c8a237 mrxsmb !level! !flags!
    )

    if defined smb20 (
        call :traceadd fskm     e4ad554c-63b2-441b-9f86-fe66d8084963 smb20 !smb20level! !smb20flags!
    ) else (
        call :traceadd fskm     e4ad554c-63b2-441b-9f86-fe66d8084963 smb20 !level! !flags!
    )
)

if not defined ca (
    @rem witness / ccf
    call :traceadd fskm 47eba62c-87e6-4564-9946-0dd4e361ed9b witnesscli
    call :traceadd fskm 17efb9ce-8cab-4f19-8b96-0d021d9c76f1 ccffilter

    @rem csc
    call :traceadd fskm 89d89015-c0df-414c-bc48-f50e114832bc cscservice
    call :traceadd fskm 791cd79c-65b5-48a3-804c-786048994f47 fastsync
    call :traceadd fskm d5418619-c167-44d9-bc36-765beb5d55f3 dcluser
    call :traceadd fskm 1f8b121d-45b3-4022-a9fb-3857177a65c1 peerdist

    @rem nfs
    call :traceadd fskm 355c2284-61cb-47bb-8407-4be72b5577b0 nfsrdr
)

goto :eof

@@@@@@@@@
:rpcxdron
call :traceadd rpcxdr   94b45058-6f59-4696-b6bc-b23b7768343d rpcxdr
call :traceadd rpcxdr   53c16bac-175c-440b-a266-1e5d5f38313b rpcxdr
goto :eof

@@@@@@@@@
:secon
call :traceadd sec      6b510852-3583-4e2d-affe-a67f9f223438 kerberos 7 0x43
call :traceadd sec      5bbb6c18-aa45-49b1-a15f-085f7ed0aa90 ntlm 7 0x15003
call :traceadd sec      5af52b0d-e633-4ead-828a-4b85b8daac2b negoexts 7 0x73
call :traceadd sec      2a6faf47-5449-4805-89a3-a504f3e221a6 pku2u 7 0x1f3
goto :eof

@@@@@@@@@
:fsumon
@rem csc
call :traceadd fsum     361f227c-aa14-4d19-9007-0c8d1a8a541b cscnet
call :traceadd fsum     0999b701-3e5d-4998-bc58-a775590a55d9 cscdll
call :traceadd fsum     19ee4cf9-5322-4843-b0d8-bab81be4e81e cscapi
call :traceadd fsum     66418a2a-72af-4c1a-9c84-42f6865563bd cscui
call :traceadd fsum     5e23b838-5b71-47e6-b123-6fe02ef573ef cscum
@rem dav
call :traceadd fsum     91efb5a1-642d-42a4-9821-f15c73064fb5 WebClnt
goto :eof

@@@@@@@@@
:srvon
call :traceadd srv      3121cf5d-c5e6-4f37-be86-57083590c333 srvdl

if defined brief (
    set level=0
) else (
    set level=7
)

call :traceadd srv      2744f0b7-8455-44f8-9b64-5f589f9d163a srv2 !level!
call :traceadd srv      c0183094-fdc6-493f-a3e8-697224f83f6f srvnet !level!
call :traceadd srv      d8e0c67b-7d87-48b6-9290-42126e66faee srvsvc !level!

if defined brief (
    set level=3
) else (
    set level=7
)

call :traceadd srv      c5a38574-9827-4c24-b8fb-d6635475566f resumekeyfilter !level!

if defined brief (
    set level=2
) else (
    set level=7
)

call :traceadd srv      c73e561f-c5b4-4a82-9b63-34bde5718e61 witnesssvc !level!
goto :eof

@@@@@@@@@
:smbhashon
call :traceadd smbhash  48be2803-12c0-4932-aa80-93372d5a9114 smbhash
goto:eof

@@@@@@@@@
:nfson
call :traceadd nfs      cc9a5284-cc3e-4567-b3f6-3eb24e7cfec5 msnfsfltguid
call :traceadd nfs      3c33d8b3-66fa-4427-a31b-f7dfa429d78f nfssvrguid
call :traceadd nfs      fc33d8b3-66fa-4427-a31b-f7dfa429d78f nfssvrguid2
call :traceadd nfs      57294efd-c387-4e08-9144-2028e8a5cb1a nfssvrnlmguid
call :traceadd nfs      f3bb9731-1d9f-4b8e-a42e-203bf1a32300 nfs4svrguid
call :traceadd nfs      e18a05dc-cce3-4093-b5ad-211e4c798a0d portmapguid
goto :eof

@@@@@@@@@
:fron
call :traceadd fr       2955e23c-4e0b-45ca-a181-6ee442ca1fc0 fr 4 0x1f
call :traceadd fr       6b6c257f-5643-43e8-8e5a-c66343dbc650 UstCommon 7 0x0fffffff
goto :eof

@@@@@@@@@
:dfsnon
call :traceadd dfsn     27246e9d-b4df-4f20-b969-736fa49ff6ff dfsn
goto :eof

@@@@@@@@@
:nbton
call :traceadd nbt      bca7bd7f-b0bf-4051-99f4-03cfe79664c1 nbtsmb
goto :eof

@@@@@@@@@
:tcpon
if %cli% gtr 1 (
    rem - tcp-only == flags 0x80 from the original script
    set flags=0x1080
    set level=7
) else (
    set flags=0x1000
    set level=2
)

call :traceadd tcp      eb004a05-9b1a-11d4-9123-0050047759bc tcp !level! !flags!
goto :eof

@@@@@@@@@
:quicon
call :traceadd quic     ff15e657-4f26-570e-88ab-0796b258d11c quic
goto :eof

@@@@@@@@@
:dnson
call :traceadd dns      609151dd-04f5-4da7-974c-fc6947eaa323 dnsapi 7 0x00797fc0
call :traceadd dns      f230b1d5-7dfd-4da7-a3a3-7e87b4b00ebf dns
goto :eof

@@@@@@@@@
:csvfson
call :traceadd csvfs    d82dba12-8b70-49ee-b844-44d0885951d2 csvfs 5 0xffff
goto :eof

@@@@@@@@@
:csvflton
call :traceadd csvflt   b421540c-1fc8-4c24-90cc-c5166e1de302 csvflt 5 0xffff
goto :eof

@@@@@@@@@
:csvvbuson
call :traceadd csvvbus  4e6177a5-c0a7-4d9b-a686-56ed5435a904 csvvbus 5 0xffff
goto :eof

@@@@@@@@@
:csvnflton
call :traceadd csvnflt  4e6177a5-c0a7-4d9b-a686-56ed5435a908 csvnflt 5 0xffc3
goto :eof

@@@@@@@@@
:sron
call :traceadd sr      8e37fc9c-8656-46da-b40d-34d97a532d09 wvrfguid
call :traceadd sr      634af965-fe67-49cf-8268-af99f62d1a3e wvrsvcguid
call :traceadd sr      fadca505-ad5e-47a8-9047-b3888ba4a8fc wvrcimprov
goto :eof

::
::::::::::::::::::::::::::::::::::::::::
:: Parameter Validation and Parsing
::::::::::::::::::::::::::::::::::::::::
::
:: :detectMode
:: detects operation mode
:: @return %mode%: 'on', 'off', or 'snapshot'
:detectMode
set mode=
:detectModeInnner
for %%i in (clion srvon) do (
    if /i "%~1" equ "%%i" (
        if "!mode!" neq "" exit /b 1
        set mode=on
        exit /b 0
    )
)
for %%i in (off clioff srvoff) do (
    if /i "%~1" equ "%%i" (
        if "!mode!" neq "" exit /b 1
        set mode=off
        exit /b
    )
)
if /i "%~1" equ "snapshot" (
    if "!mode!" neq "" exit /b 1
    set mode=snapshot
    exit /b
)
shift
if "%~1" neq "" goto :detectModeInnner
if "%mode%" equ "" exit /b 1
exit /b 0
::
:: :getCoreOnly
:: @return 1 iff 'core' is in arugments
:getCoreOnly
if /i "%~1" equ "core" (
    exit /b 1
)
shift
if "%~1" neq "" goto :getCoreOnly
exit /b 0
::
::::::::::::::::::::::::::::::::::::::::
:: Persistance Utilities
::::::::::::::::::::::::::::::::::::::::
:: :persistSet
:: Sets a value to persist in the registry
:: @param 1 registry value name
:: @param 2 registry value data
:persistSet
reg.exe add "HKCU\SOFTWARE\Microsoft\t.cmd-state" /v %1 /d %2 /f > NUL
exit /b
::
:: :persistGet
:: Creates key in registry to store settings
:: @param 1 name of environment variable to set
:: @param 2 registry value name
:: @param 3 default value (optional)
:persistGet
set %1=%3
(for /F "tokens=2*" %%a in ('reg query "HKCU\SOFTWARE\Microsoft\t.cmd-state" /v %2') do set %1=%%b) 2>NUL
exit /b
::
:: :persistClear
:: Clear a value from the registry
:: @param 1 registry value name
:persistClear
reg.exe delete "HKCU\SOFTWARE\Microsoft\t.cmd-state" /v %1 /f >NUL 2>NUL
exit /b
::
:: :persistDelete
:: Deletes all persistent registry values related to this script
:persistDelete
reg delete "HKCU\SOFTWARE\Microsoft\t.cmd-state" /f >NUL 2>NUL
exit /b
::
:: :dopersist
:: @param 1 environment variable to persist in the registry
:: @param %mode%: "on", "off", or "snapshot"
:: Stores settings in registry when %mode% is "on"; loads them otherwise
:dopersist
if /i "%mode%" equ "on" (
    if defined %1 (
        call :persistSet %1 !%1!
    ) else (
        call :persistClear %1
    )
) else (
    call :persistGet %1 %1
)
exit /b
::
::::::::::::::::::::::::::::::::::::::::
:: File Utitlities
::::::::::::::::::::::::::::::::::::::::
::
:: :toolsearch
:: Search for a tool in %PATH% and sets the variable exe to point to its full path.
:: @param 1 Name of the tool EXE
:: @return Sets %tool% to %1 if tool is found in path; %exe% set to expanded path or
:: cleared if not found.
:toolsearch
if exist "%CD%\%1" (
    set tool=%1
    goto :eof
)
for %%i in (%1) do (set exe=%%~$PATH:i)
if "!exe!" neq "" (
    set tool=%1
)
goto :eof
::
:: :mktemp
:: Find a non-existing temporary file with a specified prefix and extension
:: @param 1 variable to set
:: @param 2 path prefix
:: @param 3 file extension
:mktemp
set %1=%~2-!random!.%~3
if exist "!%1!" goto :mktemp
goto :eof
::
:: :mkstatedir
:: Create a temporary directory to store state files
:: Does not require delayed expansion.
:: @param 1 path prefix
:: @return %statedir%
:mkstatedir
set statedir=%~1-%random%
if exist "%statedir%" goto :mkstatedir
mkdir "%statedir%" >NUL 2>&1
if errorlevel 1 goto :mkstatedir
goto :eof
::
::::::::::::::::::::::::::::::::::::::::
:: Base interface to abstract between differences in NetSH, LogMan, and TraceLog
::
:: :traceon
:: Create a tracing session with the given name prior to adding trace providers.
:: @param 1 etl session name
::
:: :traceadd
:: Add a provider to the tracing session.
:: @param 1 etl session name
:: @param 2 guid
:: @param 3 display name
:: @param 4 optional level
:: @param 5 optional flags
::
:: :traceoff
:: Disable tracing for a given session.
:: @param 1 etl session name
::::::::::::::::::::::::::::::::::::::::
::
:traceon
if %single% equ 0 (
    call :traceon-%tool% %1
    if not errorlevel 1 ( set disp=started %1 ^<- )
)
goto :eof

:traceadd
setlocal
if "%~4" equ "" (
        set level=7
) else (
        set level=%4
)

if "%5" equ "" (
        set flags=0x7fffffff
) else (
        set flags=%5
)
if %single% equ 0 call :traceadd-%tool% %1 %2 %3 %level% %flags%
if %single% geq 1 call :traceadd-%tool% %NdisCapTraceSession% %2 %3 %level% %flags%
endlocal
if not errorlevel 1 ( if "%~3" neq "" set disp=!disp!%~3 )
goto :eof

:traceoff
call :traceoff-%tool% %1
if not errorlevel 1 ( echo %1 -^> %1.etl )
goto :eof

::
:: LogMan Tracing Implementation
::
:traceon-logman.exe
if defined circ set circargs=-f bincirc -max !circbuf!
set file=%~1
if "%~2" neq "" set file=%~2
call :doit logman create trace -n %1 -o "%statedir%\%file%.etl" -mode localsequence -nb 16 16 -bs 2048 -ets %circargs%
goto :eof

:traceadd-logman.exe
call :doit logman update -n %1 -p {%2} %5 %4 -ets
goto :eof

:traceoff-logman.exe
call :doit logman stop -n %1 -ets
goto :eof

::
:: TraceLog Tracing Implementation
::
:traceon-tracelog.exe
if defined circ set circargs=-cir !circbuf!
set file=%~1
if "%~2" neq "" set file=%~2
call :doit tracelog -start %1 -f "%statedir%\%file%.etl" -ls -min 16 -max 16 -b 2048 -gs %circargs%
goto :eof

:traceadd-tracelog.exe
call :doit tracelog -enable %1 -guid #%2 -level %4 -flags %5
goto :eof

:traceoff-tracelog.exe
call :doit tracelog -stop %1
goto :eof


@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@rem finalization / cab generator
@rem
@rem two phase, second (*_final) is termination
:off

@rem timestamp
set timestampfile=%statedir%\timestamp.txt
echo %DATE% %TIME%> "!timestampfile!"

@rem os version data
set verfile=%statedir%\version.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /t REG_SZ > "!verfile!"

if defined nocab goto :off_nocab

@rem check for makecab.exe
for %%i in (makecab.exe) do (set exe=%%~$PATH:i)
if "!exe!" equ "" (
    echo.
    echo.WARNING: makecab.exe not found. Proceeding as if 'nocab' was specified.
    goto :off_nocab
)

@rem construct cab directive file
set dirfile=%statedir%\tracecab.ddf
set cabname=t %computername% %date:/=-% %time::=-%.cab

echo .set CabinetName1="!cabname!"       >  !dirfile!
echo .set CompressionType=LZX            >> !dirfile!
echo .set DiskDirectory=.                >> !dirfile!
echo .set DiskDirectory1=.               >> !dirfile!
echo .set InfFileName=nul                >> !dirfile!
echo .set RptFileName=nul                >> !dirfile!
echo .set maxdisksize=0                  >> !dirfile!
call :addfile "!timestampfile!"
call :addfile "!verfile!"
call :addfile "!servicefile!"
call :addfile "!taskfile!"
for %%i in (!etl! !evtx!) do call :addfile "%statedir%\%%i"
for %%i in (!bins!) do (
        if exist "%systemroot%\system32\%%i" (
                call :addfile "%systemroot%\system32\%%i" bin\
        ) else if exist "%systemroot%\system32\drivers\%%i" (
                call :addfile "%systemroot%\system32\drivers\%%i" bin\
        )
)

echo ---
makecab /f "!dirfile!"
if !errorlevel! neq 0 (
    echo.ERROR: failed to compress trace files
    goto :off_nocab
)

echo ---
if defined bins echo compressed: matching system binaries
echo.compressed: version info +!etl!
echo.
echo.Traces are in:
echo.%CD%\!cabname!
echo.
echo.done.

@rem cleanup
call :doit del "!servicefile!"
call :doit del "!taskfile!"
call :doit del "!dirfile!"
call :doit del "!verfile!"
call :doit del "!timestampfile!"
for %%i in (!etl! !evtx!) do call :doit del "%statedir%\%%i"
goto :off_final

@rem nocab or cab failure: print location of etl files.
:off_nocab
echo.
echo.
echo. Trace files were not compressed. They are located in:
echo. %statedir%

@rem finalization for off state
:off_final
if "%mode%" equ "snapshot" (
        set mode=on
        if defined nocab (
                @rem create new statedir
                call :mkstatedir "%TEMP%\t"
                call :persistSet statedir "!statedir!"
        )
        goto :snapshot-restart
)
if not defined nocab call :doit rmdir "!statedir!"
call :persistDelete
endlocal
goto :eof

@rem finalization for on state
:on_final
if %single% geq 1 call :disp
endlocal
goto :eof

@@@@@@@@@@@@@@@@@@@@@@@@@@@@
::
:: :addfile
:: Adds a file to the CAB manifest
:: Note: Files may be located in directories containing spaces,
:: but the files themselves must not have spaces in their names
:: @param 1 file to add
:: @param 2 subdirectory to place in cab file
:: (must be followed by '\' and not contain spaces)
:addfile
if exist %1 (
echo.%~s1        %~2%~nx1 >> !dirfile!
)
goto :eof

:doit
%* >nul
if errorlevel 1 ( echo failed: %* )
goto :eof

:disp
echo.!disp!
goto :eof

@rem Check for circular buffer option and buffer size.
:checkcirc
for /f "tokens=1,2 delims=:" %%i in ("%1") do (
    if %%i equ circ (

        set circ=1
        set circbuf=%%j
        if "%%j" equ "" set circbuf=50
        echo Enabling circular buffer of size !circbuf! MB
        exit /b 0
    )
)
exit /b 1

@rem Check for specific driver, flags and level.
:checkdriver

for /f "tokens=1,2,3 delims=:" %%i in ("%1") do (
    if %%i equ rdbss (

        set rdbss=1
        set rdbssflags=%%j
        set rdbsslevel=%%k
        exit /b 0
    ) else if %%i equ mrxsmb (

        set mrxsmb=1
        set mrxsmbflags=%%j
        set mrxsmblevel=%%k
        exit /b 0
    ) else if %%i equ smb20 (

        set smb20=1
        set smb20flags=%%j
        set smb20level=%%k
        exit /b 0
    )
)
exit /b 1

