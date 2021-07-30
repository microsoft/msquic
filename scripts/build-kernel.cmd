call C:\ewdk\BuildEnv\SetupBuildEnv.cmd
msbuild msquic.kernel.sln -t:restore -p:ResorePackagesConfig=true
msbuild msquic.kernel.sln
