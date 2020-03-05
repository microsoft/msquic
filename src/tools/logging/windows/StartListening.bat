wevtutil um ..\..\..\manifest\MsQuicEtw.man
wevtutil im ..\..\..\manifest\MsQuicEtw.man /rf:c:\Source\msquic\artifacts\windows\bin\Debug\msquic.dll /mf:c:\Source\msquic\artifacts\windows\bin\Debug\msquic.dll /pf:c:\Source\msquic\artifacts\windows\bin\Debug\msquic.dll

wpr -start ..\..\..\manifest\MsQuic.wprp
