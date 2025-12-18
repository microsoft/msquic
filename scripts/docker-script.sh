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
    apt-get install -y ./artifacts/libmsquic_*.deb
}

install_dependencies_rpm()
{
    yum update -y
    find -name "libmsquic*.rpm" -exec yum localinstall -y {} \;
}

install_dependencies_opensuse()
{
    zypper ref
    find -name "libmsquic*.rpm" -exec zypper install --allow-unsigned-rpm -y {} \;
}

install_libmsquic_azure_linux()
{
    tdnf update -y
    find -name "libmsquic*.rpm" -exec tdnf install -y {} \;
}

install_libmsquic_alpine()
{
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

# Run .NET 10 self-contained test if available
if [ -f /main/src/cs/QuicSimpleTest/artifacts/net10.0/QuicHello.net10.0 ]; then
    echo "Running .NET 10 QUIC test..."
    chmod +x /main/src/cs/QuicSimpleTest/artifacts/net10.0/QuicHello.net10.0
    /main/src/cs/QuicSimpleTest/artifacts/net10.0/QuicHello.net10.0
fi

# Run .NET 9 self-contained test if available
if [ -f /main/src/cs/QuicSimpleTest/artifacts/net9.0/QuicHello.net9.0 ]; then
    echo "Running .NET 9 QUIC test..."
    chmod +x /main/src/cs/QuicSimpleTest/artifacts/net9.0/QuicHello.net9.0
    /main/src/cs/QuicSimpleTest/artifacts/net9.0/QuicHello.net9.0
fi
