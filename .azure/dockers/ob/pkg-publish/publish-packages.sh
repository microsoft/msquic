#!/bin/bash
while getopts i:s:f: flag
do
    case "${flag}" in
        i) AADClientId=${OPTARG};;
        s) AADClientSecret=${OPTARG};;
        f) FilePath=${OPTARG};;
    esac
done
Extension=`echo "${FilePath##*.}" | tr '[:upper:]' '[:lower:]'`
echo "AADClientId: $AADClientId"
echo "FilePath: $FilePath"
ls -lsa $FilePath
echo "Ext: $Extension"
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
# Repos where libmsquic has been published:
# yum|582bd4c5ae062a5d0fec5b8b|microsoft-rhel7.3-prod
# yum|584a0f48d6a6e37205720776|microsoft-sles12-prod
# yum|59d40cdcf3c7fa07032ce385|microsoft-centos7-prod
# yum|5c38ea9dea0fc9f93bd67db4|microsoft-opensuse15-prod
# yum|5c3d1796ea0fc9f93bd67def|microsoft-sles15-prod
# yum|5e5ed94a523a8019fe47607e|microsoft-centos8-prod
# yum|5e8526cde45fff4588da61f9|microsoft-fedora32-prod
# yum|5f7e2cfb68e42e6e7085f4df|microsoft-fedora33-prod
# yum|6001dd94435efd1330acd076|microsoft-rhel8.1-prod
# yum|606e1da573e50659b0803a7b|microsoft-fedora34-prod
# yum|6271bc683ac6d73aa84d6737|microsoft-fedora36-prod
# yum|6400e6f92dd6874e6880b590|microsoft-fedora37-prod
# yum|60b80feccb16ed2040bca3dd|cbl-mariner-1.0-prod-Microsoft-x86_64-rpms
# yum|61a6c6d4ea3a77190f1f6795|cbl-mariner-2.0-prod-Microsoft-x86_64
# yum|61a6c6d4ea3a7731681f6796|cbl-mariner-2.0-prod-Microsoft-aarch64
# apt|582bd623ae062a5d0fec5b8c|microsoft-ubuntu-xenial-prod
# apt|599211761cc20bce4a8ab950|microsoft-debian-stretch-prod
# apt|5a9dc3f2424a5c053cc3ff2e|microsoft-ubuntu-bionic-prod
# apt|5d23b16c9a6e3b375bbba42e|microsoft-debian-buster-prod
# apt|5e852952e45fffa1beda61fe|microsoft-ubuntu-focal-prod
# apt|5f7e2d6668e42e03f785f4e0|microsoft-ubuntu-groovy-prod
# apt|606e057173e5060519803a74|microsoft-ubuntu-hirsute-prod
# apt|611ab3a32acdcd0744c8c841|microsoft-debian-bullseye-prod
# apt|61faea6cea3a770ab120ac8a|microsoft-ubuntu-jammy-prod
DebRepos=(
    582bd623ae062a5d0fec5b8c
    599211761cc20bce4a8ab950
    5a9dc3f2424a5c053cc3ff2e
    5d23b16c9a6e3b375bbba42e
    5e852952e45fffa1beda61fe
    5f7e2d6668e42e03f785f4e0
    606e057173e5060519803a74
    611ab3a32acdcd0744c8c841
    61faea6cea3a770ab120ac8a
    5d16326637164fbc1139c4e1
    )
RPMRepos=(
    582bd4c5ae062a5d0fec5b8b
    584a0f48d6a6e37205720776
    59d40cdcf3c7fa07032ce385
    5c38ea9dea0fc9f93bd67db4
    5c3d1796ea0fc9f93bd67def
    5e5ed94a523a8019fe47607e
    5e8526cde45fff4588da61f9
    5f7e2cfb68e42e6e7085f4df
    6001dd94435efd1330acd076
    606e1da573e50659b0803a7b
    60b80feccb16ed2040bca3dd
    60b80feccb16edcf4bbca3de
    61a6c6d4ea3a77190f1f6795
    61a6c6d4ea3a7731681f6796
    6271bc683ac6d73aa84d6737
    6400e6f92dd6874e6880b590
    )
echo $ConfigString | jq > ~/.repoclient/prodconfig.json
jsonOut=""
if [ $Extension = "rpm" ]
then
    echo "Uploading the package to RPM repos..."
    for Repo in "${RPMRepos[@]}"
    do
        echo "Uploading to repo $Repo"
        res=`repoclient -s pmc -v v3 package add -k $FilePath -r $Repo`
        echo $res | jq
        jsonOut+=$res
    done
fi
if [ $Extension = "deb" ]
then
    echo "Uploading the package to DEB repos..."
    for Repo in "${DebRepos[@]}"
    do
        echo "Uploading to repo $Repo"
        res=`repoclient -s pmc -v v3 package add -k $FilePath -r $Repo`
        echo $res | jq
        jsonOut+=$res
    done
fi
echo "submissionIds:"
echo $jsonOut | jq -r '.message.submissionId?'
