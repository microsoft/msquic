#!/bin/bash
while getopts i:s:f:r: flag
do
    case "${flag}" in
        i) AADClientId=${OPTARG};;
        s) AADClientSecret=${OPTARG};;
        f) FilePath=${OPTARG};;
        r) Repo=${OPTARG};;
    esac
done
echo "AADClientId: $AADClientId"
echo "FilePath: $FilePath"
ls -lsa $FilePath
ConfigString="
{
    \"server\": \"azure-apt-cat.cloudapp.net\",
    \"port\": \"443\",
    \"AADClientId\": \"$AADClientId\",
    \"AADClientSecret\": \"$AADClientSecret\",
    \"AADResource\": \"https://microsoft.onmicrosoft.com/945999e9-da09-4b5b-878f-b66c414602c0\",
    \"AADTenant\": \"72f988bf-86f1-41af-91ab-2d7cd011db47\",
    \"AADAuthorityUrl\": \"https://login.microsoftonline.com\",
    \"repositoryId\": \"5ca39edc03f790615107e1e1\"
}
"

echo $ConfigString | jq > ~/.repoclient/prodconfig.json
echo "publish-docker: Uploading to $FilePath to repo $Repo"
res=`repoclient -s pmc -v v3 package add -k $FilePath -r $Repo`
echo $res | jq
echo "publish-docker: submissionId:"
echo $res | jq -r '.message.submissionId?'
