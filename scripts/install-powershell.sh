#!/bin/sh

wget -q https://packages.microsoft.com/config/ubuntu/$1/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo add-apt-repository universe
sudo apt-get install -y powershell apt-transport-https
