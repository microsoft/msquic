
:: Import our ETW manifest.
wevtutil im manifest\MsQuicEtw.man ^
    /rf:%cd%\artifacts\windows\bin\debug\msquic.dll ^
    /mf:%cd%\artifacts\windows\bin\debug\msquic.dll

:: Start log collection.
mkdir artifacts\logs
netsh trace start sessionname=quic ^
    overwrite=yes report=dis correlation=dis maxSize=256 ^
    traceFile=artifacts\logs\quic.etl ^
    provider=Microsoft-Quic level=0x5 keywords=0xE0000100

:: Run the tests.
mkdir artifacts\dumps
bld\windows\procdump\procdump64.exe ^
    -ma -e -b -l -accepteula -x artifacts\dumps ^
    artifacts\windows\bin\debug\msquictest.exe ^
        --gtest_filter=%1 ^
        --gtest_output=xml:artifacts\logs\windows-test-results.xml

:: Stop log collection.
netsh trace stop sessionname=quic

:: Convert ETW logs to text.
netsh trace convert ^
    artifacts\logs\quic.etl ^
    output=artifacts\logs\quic.log ^
    overwrite=yes
