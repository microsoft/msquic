#! /bin/sh

# The argument is private key path

sudo cp $1.pub /etc/apk/keys/
sudo cp $1 /home/packaging/.abuild/

sudo echo PACKAGER_PRIVKEY="$1" > /home/packaging/.abuild/abuild.conf

sudo chown -R packaging:abuild /home/packaging/.abuild
