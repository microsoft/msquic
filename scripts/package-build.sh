#! /bin/sh

set -e
apk add --upgrade sudo alpine-sdk

git config --global user.name "Microsoft QUIC Team"
git config --global user.email "quicdev@microsoft.com"

# Add the packaging user to the abuild group
adduser -D packaging -G abuild

# Give the packaging user sudo access
echo "packaging ALL=(ALL)       NOPASSWD: ALL" > /etc/sudoers.d/packaging

mkdir -p /var/cache/distfiles
chmod a+w /var/cache/distfiles

mkdir -p /home/packaging/github-actions/packages/
chown -R packaging:abuild /home/packaging/github-actions/packages/

mkdir -p /home/packaging/tools
cp /msquic/APKBUILD /home/packaging/tools
chown -R packaging:abuild /home/packaging/tools

su packaging -c "abuild-keygen -n"
find /home/packaging/.abuild -name '*.rsa' -exec /msquic/scripts/alpine-configure-packaging-key.sh {} \;

# msquic is using submodules and we need to get them inside
cd /home/packaging/tools
su packaging -c "abuild -r"

cp /home/packaging/packages/packaging/**/*.apk /artifacts
