#!/bin/bash

while getopts i:c:f:r:n:l: flag
do
    case "${flag}" in
        i) ClientId=${OPTARG};;
        c) Cert=${OPTARG};;
        f) Folder=${OPTARG};;
        r) Repo=${OPTARG};;
        n) NameFilter=${OPTARG};;
    esac
done

ConfigString="
[prod]\n
base_url = \"https://pmc-ingest.trafficmanager.net/api/v4\"\n
msal_client_id = \"$ClientId\"\n
msal_scope = \"api://d48bb382-20ec-41b9-a0ea-07758a21ccd0/.default\"\n
msal_cert_path = \"~/.config/pmc/auth.pem\"\n
msal_SNIAuth = true\n
msal_authority = \"https://login.microsoftonline.com/MSAzureCloud.onmicrosoft.com\"\n
"

mkdir -p ~/.config/pmc/
echo -e $ConfigString > ~/.config/pmc/settings.toml
cp $Cert ~/.config/pmc/auth.pem
pmc() {
    docker run -t --volume ~/.config/pmc:/root/.config/pmc --volume "$Folder":/root/packages --rm mcr.microsoft.com/pmc/pmc-cli "$@"
}
IFS='-' read -ra parts <<< "$Repo"
if [ "${parts[-1]}" = "apt" ]; then
    echo "apt repo"
    release=${parts[2]}
    echo "Release name: $release"
    archesString=`pmc repo release list "$Repo" | jq -r '.results[] | select(.name == "lunar") | .architectures[]'`
    readarray -t arches <<< "$archesString"
    echo "Supported arches in $Repo: ${arches[@]}"
else
    echo "yum repo"
    release=""
fi

for filename in `find $Folder -maxdepth 1 -type f -name "$NameFilter"`; do
    basefilename=`basename $filename`
    if [ ! -z "$release" ]; then
        echo -n "Checking if $basefilename is supported by the repo: "
        match_found=false
        for arch in "${arches[@]}"; do
            if [[ "$basefilename" == *"$arch"* ]]; then
                match_found=true
            fi
        done

        if [ "$match_found" = false ]; then
            echo "❌"
            continue
        else
            echo "✅"
        fi
    fi
    echo "Uploading $filename to $Repo"
    packageId=`pmc -q --id-only package upload /root/packages/$basefilename | tr -d '\r'`
    echo "package ID: $packageId"
    pmc repo package update --add-packages "$packageId" "$Repo" $release
done

pmc repo publish "$Repo"
