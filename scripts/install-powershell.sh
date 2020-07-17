#!/bin/sh

wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
chmod +x ./dotnet-install.sh
./dotnet-install.sh -c Current

echo "##vso[task.setvariable variable=PATH]${PATH}:${HOME}/.dotnet"
echo "##vso[task.setvariable variable=PATH]${PATH}:${HOME}/.dotnet/tools"
echo "##vso[task.setvariable variable=DOTNET_ROOT]${HOME}/.dotnet"

export PATH="$PATH:$HOME/.dotnet"
export PATH="$PATH:$HOME/.dotnet/tools"
export DOTNET_ROOT="$HOME/.dotnet/"

wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo add-apt-repository universe
sudo apt-get install -y powershell
