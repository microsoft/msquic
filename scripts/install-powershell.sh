#!/bin/sh

wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo add-apt-repository universe
sudo apt-get install -y powershell apt-transport-https
sudo apt-get update
sudo apt-get install -y dotnet-sdk-3.1
sudo ldconfig

echo "##vso[task.setvariable variable=PATH]${PATH}:${Home}/.dotnet/tools"

echo "##vso[task.setvariable variable=DOTNET_ROOT]$(dirname $(realpath $(which dotnet)))"
