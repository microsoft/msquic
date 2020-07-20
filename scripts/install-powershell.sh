#!/bin/sh

wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo add-apt-repository universe
sudo apt-get install -y powershell apt-transport-https

echo "$AGENT_TOOLSDIRECTORY/dotnet"
echo "##vso[task.setvariable variable=DOTNET_ROOT]$AGENT_TOOLSDIRECTORY/dotnet
