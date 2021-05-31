set SOLUTION_DIR=%1
set PLATFORM_ARG=%2
set CONFIGURATION_ARG=%3
set QUIC_BUILD_DIR=%SOLUTION_DIR%\build\winkernel\%PLATFORM_ARG%_%CONFIGURATION_ARG%_schannel

mkdir %QUIC_BUILD_DIR%\inc

cmd /c %SOLUTION_DIR%\scripts\generate_kernel_clog.bat %QUIC_BUILD_DIR% %SOLUTION_DIR% %SOLUTION_DIR%\src\core CORE
cmd /c %SOLUTION_DIR%\scripts\generate_kernel_clog.bat %QUIC_BUILD_DIR% %SOLUTION_DIR% %SOLUTION_DIR%\src\platform PLATFORM
cmd /c %SOLUTION_DIR%\scripts\generate_kernel_clog.bat %QUIC_BUILD_DIR% %SOLUTION_DIR% %SOLUTION_DIR%\src\bin\winkernel BIN
cmd /c %SOLUTION_DIR%\scripts\generate_kernel_clog.bat %QUIC_BUILD_DIR% %SOLUTION_DIR% %SOLUTION_DIR%\src\test\bin\winkernel TEST_BIN
cmd /c %SOLUTION_DIR%\scripts\generate_kernel_clog.bat %QUIC_BUILD_DIR% %SOLUTION_DIR% %SOLUTION_DIR%\src\test\lib TEST_LIB
mc.exe -um -h %QUIC_BUILD_DIR%\inc -r %QUIC_BUILD_DIR%\inc %SOLUTION_DIR%\src\manifest\MsQuicEtw.man
