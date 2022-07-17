#!/bin/sh

Platform=`uname`
if [ "$Platform" = "Linux" ]; then
    Distribution=`awk -F= '/^NAME/{print $2}' /etc/os-release`
    if [ "$Distribution" = "\"Ubuntu\"" -o "$Distribution" = "\"Debian GNU/Linux\"" ]; then
        wget -q https://packages.microsoft.com/config/ubuntu/$1/packages-microsoft-prod.deb
        sudo dpkg -i packages-microsoft-prod.deb
        sudo apt-get update
        sudo add-apt-repository universe
        sudo apt-get install -y powershell apt-transport-https
    else
        echo $Distribution is not supported
    fi
elif [ "$Platform" = "Darwin" ]; then
    brew update
    brew install --cask powershell
else
    echo $Platform is not supported
fi
