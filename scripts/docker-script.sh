#! /bin/sh

if [ $(id -u) -ne 0 ]; then
    # Beware of how you compose the command
    echo "This script must be run as root. Running the script with sudo..."
    printf -v cmd_str '%q ' "$0" "$@"
    exec sudo su -c "$cmd_str"
    exit $?
fi

cd /main
. /etc/os-release
OS=$(echo $ID | xargs)
VERSION=$(echo $VERSION_ID | xargs)

echo "${OS} ${VERSION} is detected."

install_dependencies_apt()
{
    apt-get update
    if ! [ -f /usr/bin/dotnet ]; then
        apt-get install -y wget gzip tar
    fi
    apt-get install -y ./artifacts/libmsquic_*.deb
}

install_dependencies_rpm()
{
    yum update -y
    if ! [ -f /usr/bin/dotnet ]; then
        yum install -y wget gzip tar # .NET installing requirements
        yum install -y libicu # .NET dependencies
    fi
    find -name "libmsquic*.rpm" -exec yum localinstall -y {} \;
}

install_dependencies_opensuse()
{
    zypper ref
    if ! [ -f /usr/bin/dotnet ]; then
        zypper install -y wget gzip
    fi
    find -name "libmsquic*.rpm" -exec zypper install --allow-unsigned-rpm -y {} \;
}

# .NET is installed already on Azure Linux and Mariner images
install_libmsquic_azure_linux()
{
    if ! [ -f /usr/bin/dotnet ]; then
        tdnf install -y wget gzip tar
    fi
    tdnf update
    find -name "libmsquic*.rpm" -exec tdnf install -y {} \;
}

install_libmsquic_alpine()
{
    if ! [ -f /usr/bin/dotnet ]; then
        apk add --upgrade --no-cache wget gzip tar
    fi
    find -name "libmsquic*.apk" -exec apk add --allow-untrusted {} \;
}

if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    install_dependencies_apt
elif [ "$OS" = "centos" ] || [ "$OS" = "almalinux" ] || [ "$OS" = "rhel" ] || [ "$OS" = "fedora" ]; then
    install_dependencies_rpm
elif [ "$OS" = 'opensuse-leap' ]; then
    install_dependencies_opensuse
elif [ "$OS" = 'azurelinux' ] || [ "$OS" = 'mariner' ]; then
    install_libmsquic_azure_linux
elif [ "$OS" = 'alpine' ]; then
    install_libmsquic_alpine
else
    echo "Unsupported OS: ${OS}"
    exit 1
fi

set -e
if ! [ "$OS" = 'alpine' ]; then
    chmod +x artifacts/bin/linux/${1}_${2}_${3}/msquictest
    artifacts/bin/linux/${1}_${2}_${3}/msquictest --gtest_filter=ParameterValidation.ValidateApi
fi

# Install .NET if it is not installed
if ! [ -f /usr/bin/dotnet ]; then
    wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
    chmod +x dotnet-install.sh
    ./dotnet-install.sh --channel $4 --shared-runtime

    export PATH=$PATH:$HOME/.dotnet
    export DOTNET_ROOT=$HOME/.dotnet
fi

dotnet /main/src/cs/QuicSimpleTest/artifacts/net$4/QuicHello.net$4.dll
