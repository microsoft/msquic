
:: Install ProcDump if not already installed.
PowerShell test\get_procdump.ps1

:: Start ProcDump
mkdir artifacts\dumps
start bld\procdump\procdump64.exe -ma -e -b -accepteula -w msquictest.exe artifacts\dumps

:: Import our ETW manifest.
wevtutil im manifest\MsQuicEtw.man ^
    /rf:%cd%\artifacts\bin\Release\msquic.dll ^
    /mf:%cd%\artifacts\bin\Release\msquic.dll

:: Start log collection.
netsh trace start sessionname=quic ^
    overwrite=yes report=dis correlation=dis maxSize=1024 ^
    traceFile=artifacts\logs\quic.etl ^
    provider=Microsoft-Quic level=0x5

:: Run the tests.
artifacts\bin\Release\msquictest.exe ^
    --gtest_output=xml:artifacts\logs\windows-test-results.xml

:: Stop log collection.
netsh trace stop sessionname=quic

:: Convert ETW logs to text.
netsh trace convert ^
    artifacts\logs\quic.etl ^
    output=artifacts\logs\quic.log ^
    overwrite=yes
