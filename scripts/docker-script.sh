#! /bin/bash
set -e
cd /main
OS=$(echo $(awk -F= '$1=="ID" { print $2 ;}' /etc/os-release) | xargs)
VERSION=$(echo $(awk -F= '$1=="VERSION_ID" { print $2 ;}' /etc/os-release) | xargs)

echo "${OS} ${VERSION} is detected."

install_dependencies_apt()
{
    sudo apt-get update
    sudo apt-get install --fix-broken
    sudo apt-get install -y wget git gzip tar
    # Remove the existing libmsquic package and dependencies for Ubuntu
    sudo apt-get remove -y libmsquic libnuma1
    if [[ "$OS" == "ubuntu" ]] && [[ "$VERSION" == "24.04" ]]; then
        sudo apt-get remove -y libxdp1 libnl-route-3-200
    fi
    sudo apt-get install -y ./artifacts/libmsquic_*.deb
}

install_dependencies_rpm()
{
    sudo yum update -y
    sudo yum install -y wget git gzip tar libicu
    # Remove the existing libmsquic package and dependencies for Ubuntu
    sudo yum remove -y libmsquic numactl-libs
    sudo find -name "libmsquic*.rpm" -exec yum localinstall -y {} \;
}

install_dependencies_opensuse()
{
    sudo zypper ref
    sudo zypper install -y wget git gzip
    # Remove the existing libmsquic package and dependencies for Ubuntu
    sudo zypper remove -y libmsquic libnuma1
    sudo find -name "libmsquic*.rpm" -exec zypper install --allow-unsigned-rpm -y {} \;
}

if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
    install_dependencies_apt
elif [[ "$OS" == "centos" ]] || [[ "$OS" == "almalinux" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "fedora" ]]; then
    install_dependencies_rpm
elif [[ "$OS" == 'opensuse-leap' ]]; then
    install_dependencies_opensuse
else
    echo "Unsupported OS: ${OS}"
    exit 1
fi

sudo chmod +x artifacts/bin/linux/${1}_${2}_${3}/msquictest
sudo artifacts/bin/linux/${1}_${2}_${3}/msquictest --gtest_filter=ParameterValidation.ValidateApi
if [ $? -ne 0 ]; then
    exit $?
fi

cd /main

sudo wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
sudo chmod +x dotnet-install.sh
sudo ./dotnet-install.sh --channel $4

export DOTNET_ROOT=/root/.dotnet
export PATH=$PATH:/root/.dotnet

sudo /root/.dotnet/dotnet src/cs/QuicSimpleTest/artifacts/net$4/QuicHello.dll