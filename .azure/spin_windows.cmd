
:: Run spinquic for a while.
mkdir artifacts\dumps
bld\windows\procdump\procdump64.exe ^
    -ma -e -b -l -accepteula -x artifacts\dumps ^
    artifacts\windows\bin\debug\spinquic.exe both -timeout:300000

:: Print any dump files that might be generated.
dir artifacts\dumps
