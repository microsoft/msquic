@echo off

set QUIC_BUILD_DIR=%1
set CMAKE_SOURCE_DIR=%2
set CMAKE_PROJECTDIR=%3
set SCOPE_PREFIX=%4

echo QUIC_BUILD_DIR=%QUIC_BUILD_DIR%
echo CMAKE_SOURCE_DIR=%CMAKE_SOURCE_DIR%
echo CMAKE_PROJECTDIR=%CMAKE_PROJECTDIR%
echo SCOPE_PREFIX=%SCOPE_PREFIX%

set CMAKE_CLOG_OUTPUT_DIRECTORY=%QUIC_BUILD_DIR%\inc
set CMAKE_CLOG_BINS_DIRECTORY=%QUIC_BUILD_DIR%\submodules\clog
set CMAKE_CLOG_SIDECAR_DIRECTORY=%CMAKE_SOURCE_DIR%\src\manifest
set CLOG_SOURCE_DIRECTORY=%CMAKE_SOURCE_DIR%\submodules\clog
set CLOG_INCLUDE_DIRECTORY=%CMAKE_SOURCE_DIR%\inc
set CMAKE_CLOG_CONFIG_FILE=%CMAKE_SOURCE_DIR%\src\manifest\msquic.clog_config

echo %CMAKE_SOURCE_DIR%

if NOT EXIST %CMAKE_CLOG_BINS_DIRECTORY%\clog.exe (
    echo Building CLOG
    echo dotnet build %CLOG_SOURCE_DIRECTORY%\clog.sln\clog_coreclr.sln -o %CMAKE_CLOG_BINS_DIRECTORY%
    dotnet build %CLOG_SOURCE_DIRECTORY%\clog.sln\clog_coreclr.sln -o %CMAKE_CLOG_BINS_DIRECTORY%
)

pushd %CMAKE_PROJECTDIR%
echo CLOG Processing Directory %CMAKE_PROJECTDIR%
for %%i in (*.c* *.c operation.h stream.h connection.h TestHelpers.h) do (
    echo CLOG Processing %%i
    if EXIST %%i (
        if NOT EXIST %CMAKE_CLOG_OUTPUT_DIRECTORY%\%%i.clog.h (
            %CMAKE_CLOG_BINS_DIRECTORY%\clog.exe --developerMode -p windows_kernel --scopePrefix %SCOPE_PREFIX% -c %CMAKE_CLOG_CONFIG_FILE% -s %CMAKE_CLOG_SIDECAR_DIRECTORY%\clog.sidecar -i %%i -o %CMAKE_CLOG_OUTPUT_DIRECTORY%\%%i.clog.h
            echo %%i
        )
    )
)
popd
