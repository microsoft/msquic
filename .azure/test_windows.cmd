
:: Import our ETW manifest.
wevtutil im src\manifest\MsQuicEtw.man ^
    /rf:%cd%\artifacts\windows\bin\debug\msquic.dll ^
    /mf:%cd%\artifacts\windows\bin\debug\msquic.dll

:: Run the tests.
pwsh -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Unrestricted ^
    .\test.ps1 ^
        -Config Debug ^
        -Batch ^
        -Filter %1 ^
        -SaveXmlResults ^
        -LogProfile Basic.Light ^
        -ConvertLogs
