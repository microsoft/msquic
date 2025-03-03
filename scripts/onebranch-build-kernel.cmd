call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat
msbuild msquic.kernel.sln -p:ONEBRANCH_BUILD=true /p:Configuration=%1 /p:Platform=%2 /p:QUIC_VER_SUFFIX=-official /p:QUIC_VER_BUILD_ID=%BUILD_BUILDID% /p:QUIC_VER_GIT_HASH=%BUILD_SOURCEVERSION%
