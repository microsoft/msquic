#! /bin/sh

# Install sudo
apk add --upgrade --no-cache sudo alpine-sdk

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
