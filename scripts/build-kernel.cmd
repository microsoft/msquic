call C:\ewdk\BuildEnv\SetupBuildEnv.cmd
msbuild msquic.kernel.sln -t:restore -p:RestorePackagesConfig=true
msbuild msquic.kernel.sln
