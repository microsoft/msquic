
:: Install ProcDump if not already installed.
PowerShell .azure\get_procdump.ps1

:: Enable SChannel TLS 1.3 for client and server.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v Enabled /t REG_DWORD /d 1 /f

:: Start ProcDump
mkdir artifacts\dumps
start bld\procdump\procdump64.exe -ma -e -b -accepteula -w msquictest.exe artifacts\dumps

:: Import our ETW manifest.
wevtutil im manifest\MsQuicEtw.man ^
    /rf:%cd%\artifacts\bin\Debug\msquic.dll ^
    /mf:%cd%\artifacts\bin\Debug\msquic.dll

:: Start log collection.
netsh trace start sessionname=quic ^
    overwrite=yes report=dis correlation=dis maxSize=256 ^
    traceFile=artifacts\logs\quic.etl ^
    provider=Microsoft-Quic level=0x5 keywords=0xE0000100

:: Run the tests.
artifacts\bin\Debug\msquictest.exe ^
    --gtest_filter=%1 ^
    --gtest_output=xml:artifacts\logs\windows-test-results.xml

:: Stop log collection.
netsh trace stop sessionname=quic

:: Convert ETW logs to text.
netsh trace convert ^
    artifacts\logs\quic.etl ^
    output=artifacts\logs\quic.log ^
    overwrite=yes
