call C:\ewdk\LaunchBuildEnv.cmd
msbuild msquic.kernel.sln -t:restore -p:ResorePackagesConfig=true
msbuild msquic.kernel.sln
