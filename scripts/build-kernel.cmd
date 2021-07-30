C:\ewdk\LaunchBuildEnv.cmd
echo "Hello!"
msbuild msquic.kernel.sln -t:restore -p:ResorePackagesConfig=true
msbuild msquic.kernel.sln
