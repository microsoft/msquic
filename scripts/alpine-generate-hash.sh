#! /bin/sh
set -e
apk add --upgrade --no-cache alpine-sdk
adduser -D packaging -G abuild
cp /msquic/APKBUILD /home/packaging/
cd /home/packaging
su packaging -c "abuild checksum"
cp /home/packaging/APKBUILD /msquic/APKBUILD
