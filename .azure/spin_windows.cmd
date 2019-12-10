
:: Install ProcDump if not already installed.
PowerShell .azure\get_procdump.ps1

:: Enable SChannel TLS 1.3 for client and server.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v Enabled /t REG_DWORD /d 1 /f

:: Start ProcDump.
mkdir artifacts\dumps
start bld\procdump\procdump64.exe -ma -e -b -accepteula -w spinquic.exe artifacts\dumps

:: Run spinquic for a while.
artifacts\bin\Release\spinquic.exe both -timeout:10000

dir artifacts\dumps
