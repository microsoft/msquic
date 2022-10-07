# escape=`
FROM cdpxwin1809.azurecr.io/global/vse2019:latest

# Default .NET FX images switch shell to PS. Switch it back.
SHELL ["cmd", "/S", "/C"]

COPY win-installer-helper.psm1 C:\
COPY install*.* C:\
COPY xgameplatform.lib C:\

RUN dir C:\

RUN C:\install.cmd C:\install-ewdk.ps1

RUN C:\install.cmd C:\install-tools.ps1

RUN del C:\install*.* & `
    exit 0
