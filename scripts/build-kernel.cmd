call C:\ewdk\BuildEnv\SetupBuildEnv.cmd
msbuild msquic.kernel.sln -t:restore -p:RestorePackagesConfig=true
msbuild msquic.kernel.sln -p:ONEBRANCH_BUILD=true /p:Configuration=%1 /p:Platform=%2 /p:QUIC_VER_SUFFIX=-official /p:QUIC_VER_BUILD_ID=%BUILD_BUILDID%
