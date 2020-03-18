set SOLUTION_DIR=%1
set PLATFORM_ARG=%2
set CONFIGURATION_ARG=%3

cmd /c %SOLUTION_DIR%\scripts\generate_kernel_clog.bat CORE_KERNEL_LIB %SOLUTION_DIR% %SOLUTION_DIR%\src\core 
cmd /c %SOLUTION_DIR%\scripts\generate_kernel_clog.bat PLATFORM_KERNEL_LIB %SOLUTION_DIR% %SOLUTION_DIR%\src\platform 
cmd /c %SOLUTION_DIR%\scripts\generate_kernel_clog.bat WINKERNEL_KERNEL_LIB %SOLUTION_DIR% %SOLUTION_DIR%\src\bin\winkernel
cmd /c %SOLUTION_DIR%\scripts\generate_kernel_clog.bat TEST_BIN_KERNEL_LIB %SOLUTION_DIR% %SOLUTION_DIR%\src\test\bin\winkernel
cmd /c %SOLUTION_DIR%\scripts\generate_kernel_clog.bat TEST_LIB_KERNEL_LIB %SOLUTION_DIR% %SOLUTION_DIR%\src\test\lib 

mkdir %SOLUTION_DIR%\bld\winkernel\%PLATFORM_ARG%_%CONFIGURATION_ARG%_schannel\inc
mc.exe -um -h %SOLUTION_DIR%\bld\winkernel\%PLATFORM_ARG%_%CONFIGURATION_ARG%_schannel\inc -r %SOLUTION_DIR%\bld\winkernel\%PLATFORM_ARG%_%CONFIGURATION_ARG%_schannel\inc %SOLUTION_DIR%\src\manifest\MsQuicEtw.man
