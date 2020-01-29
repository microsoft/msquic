
:: Import our ETW manifest.
wevtutil im manifest\MsQuicEtw.man ^
    /rf:%cd%\artifacts\windows\bin\debug\msquic.dll ^
    /mf:%cd%\artifacts\windows\bin\debug\msquic.dll

:: Run the tests.
pwsh -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Unrestricted .\test.ps1 -Batch -SaveXmlResults -LogProfile Full.Light -ConvertLogs -Filter %1
