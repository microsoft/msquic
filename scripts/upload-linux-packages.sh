#!/bin/bash
while getopts i:s:f:r:n: flag
do
    case "${flag}" in
        i) AADClientId=${OPTARG};;
        s) AADClientSecret=${OPTARG};;
        f) Folder=${OPTARG};;
        r) Repo=${OPTARG};;
        n) NameFilter=${OPTARG};;
    esac
done

for filename in `find $Folder -maxdepth 1 -type f -name "$NameFilter"`; do
    basefilename=`basename $filename`
    echo "Uploading $filename to $Repo"
    docker run -v $Folder:/usr/src/hostpwd msquicdockerregistry.azurecr.io/private/msquic/publish-linux-packages:vnext -i $AADClientId -s $AADClientSecret -f /usr/src/hostpwd/$basefilename -r $Repo
done