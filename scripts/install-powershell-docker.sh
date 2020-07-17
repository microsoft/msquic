#!/bin/sh

wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
chmod +x ./dotnet-install.sh
./dotnet-install.sh -c Current --install-dir /usr/share

dotnet tool install -g powershell
