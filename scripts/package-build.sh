#! /bin/sh

./alpine-packaging-prepare-script.sh
mkdir -p /home/packaging/tools
cp APKBUILD /home/packaging/tools
chown -R packaging:abuild /home/packaging/tools

su packaging -c "abuild-keygen -n"
find /home/packaging/.abuild -name '*.rsa' -exec ./alpine-configure-packaging-key.sh {} \;

# msquic is using submodules and we need to get them inside
cd /home/packaging/tools
su packaging -c "abuild snapshot"
su packaging -c "abuild checksum"
su packaging -c "abuild -r"

mkdir -p /artifacts
cp /home/packaging/packages/packaging/**/*.apk /artifacts