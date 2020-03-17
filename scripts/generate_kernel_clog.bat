@echo off

set SCOPE_PREFIX=%1
set CMAKE_SOURCE_DIR=%2
set CMAKE_PROJECTDIR=%3
set CMAKE_CLOG_OUTPUT_DIRECTORY=%CMAKE_SOURCE_DIR%\bld\clog_kernel
set CMAKE_CLOG_BINS_DIRECTORY=%CMAKE_SOURCE_DIR%\artifacts\tools\bin\clog
set CMAKE_CLOG_SIDECAR_DIRECTORY=%CMAKE_SOURCE_DIR%\src\manifest
set CLOG_SOURCE_DIRECTORY=%CMAKE_SOURCE_DIR%\submodules\clog
set CLOG_INCLUDE_DIRECTORY=%CMAKE_SOURCE_DIR%\inc
set CMAKE_CLOG_CONFIG_FILE=%CMAKE_SOURCE_DIR%\src\manifest\msquic_windows_kernel.clog_config

echo %CMAKE_SOURCE_DIR%

if NOT EXIST %CMAKE_CLOG_BINS_DIRECTORY%\clog.exe (
	dotnet build %CLOG_SOURCE_DIRECTORY%\clog.sln\clog_coreclr.sln -o %CMAKE_CLOG_BINS_DIRECTORY%
)

pushd %CMAKE_PROJECTDIR%
for %%i in (*.c* *.c operation.h stream.h connection.h) do (
	echo CLOG Processing %%i
	if NOT EXIST %CMAKE_CLOG_OUTPUT_DIRECTORY%\%%i.clog (
		%CMAKE_CLOG_BINS_DIRECTORY%\clog.exe --scopePrefix %SCOPE_PREFIX% -c %CMAKE_CLOG_CONFIG_FILE% -s %CMAKE_CLOG_SIDECAR_DIRECTORY%\clog.sidecar -i %%i -o %CMAKE_CLOG_OUTPUT_DIRECTORY%\%%i.clog
		echo %%i
	)
)
popd

