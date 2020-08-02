#!/bin/sh

wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
dpkg -i packages-microsoft-prod.deb

apt-get update
apt-get install -y apt-transport-https
apt-get update
apt-get install -y dotnet-sdk-3.1

dotnet tool install -g powershell
wget https://github.com/microsoft/CLOG/releases/download/v0.1.4-experiment/Microsoft.Logging.CLOG.0.1.4.nupkg

mkdir nuget
mv Microsoft.Logging.CLOG.0.1.4.nupkg nuget/Microsoft.Logging.CLOG.0.1.4.nupkg
dotnet tool install --global --add-source nuget Microsoft.Logging.CLOG
