
:: Start ProcDump.
mkdir artifacts\dumps
start bld\procdump\procdump64.exe -ma -e -b -accepteula -w spinquic.exe artifacts\dumps

:: Run spinquic for a while.
artifacts\bin\debug\spinquic.exe both -timeout:300000

:: Print any dump files that might be generated.
dir artifacts\dumps
