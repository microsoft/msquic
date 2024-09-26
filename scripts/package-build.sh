#! /bin/sh

wget $REPO_URL/packaging/github-actions/APKBUILD
wget $REPO_URL/scripts/alpine-configure-packaging-key.sh
wget $REPO_URL/scripts/alpine-packaging-prepare-script.sh
chmod +x alpine-configure-packaging-key.sh
chmod +x alpine-packaging-prepare-script.sh

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

cp /home/packaging/packages/packaging/**/*.apk /artifacts