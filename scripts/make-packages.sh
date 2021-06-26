#!/bin/bash

OS=$(uname)
ARCH=$(uname -m)
FPM=`which fpm` 2>/dev/null
CONFIG=Release
VER_MAJOR=$(cat ./src/inc/msquic.ver | grep 'define VER_MAJOR'| cut -d ' ' -f 3)
VER_MINOR=$(cat ./src/inc/msquic.ver | grep 'define VER_MINOR'| cut -d ' ' -f 3)
VER_PATCH=$(cat ./src/inc/msquic.ver | grep 'define VER_PATCH'| cut -d ' ' -f 3)

if [ -z "$FPM" ]; then
  echo Install 'fpm'
  exit 1
fi

if [ "$OS" == 'Linux' ]; then
    OS=linux
    if [ "$ARCH" == 'x86_64' ]; then
        ARCH='x64'
        LIBDIR="lib64"
    else
        ARCH=x86
        LIBDIR="lib"
    fi
else
    echo Only Linux packaging is supported at the moment.
    exit 1
fi

ARTIFACTS="artifacts/bin/${OS}/${ARCH}_${CONFIG}_openssl"
if [ ! -e "$ARTIFACTS/libmsquic.so" ]; then
    echo "$ARTIFACTS/libmsquic.so" does not exist. Run build first.
    exit 1
fi
OUTPUT="artifacts/packages/${OS}/${ARCH}_${CONFIG}_openssl"

# process arguments and allow to override default values
while :; do
    if [ $# -le 0 ]; then
        break
    fi

    case $1 in
        -o|--output)
            shift
            OUTPUT=$1
            ;;
        *)
            echo unknown argument
            ;;
    esac

    shift
done

mkdir -p ${OUTPUT}

# RedHat/CentOS
fpm -f -s dir -t rpm  -n libmsquic -v ${VER_MAJOR}.${VER_MINOR}.${VER_PATCH} --license MIT --url https://github.com/microsoft/msquic \
    --package "$OUTPUT" --log error \
    "$ARTIFACTS/libmsquic.so"=/usr/${LIBDIR}/libmsquic.so \
    "$ARTIFACTS/libmsquic.lttng.so"=/usr/${LIBDIR}/libmsquic.lttng.so

# Debian/Ubuntu
if [ "$LIBDIR" == 'lib64' ]; then
    LIBDIR="lib/x86_64-linux-gnu"
fi
fpm -f -s dir -t deb  -n libmsquic -v ${VER_MAJOR}.${VER_MINOR}.${VER_PATCH} --license MIT --url https://github.com/microsoft/msquic \
    --package "$OUTPUT" --log error \
    "$ARTIFACTS/libmsquic.so"=/usr/${LIBDIR}/libmsquic.so \
    "$ARTIFACTS/libmsquic.lttng.so"=/usr/${LIBDIR}/libmsquic.lttng.so
