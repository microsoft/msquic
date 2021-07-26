#!/bin/bash

usage()
{
    echo "Usage: $0 [-output <directory>] [-config Debug]"
    exit 1
}

OS=$(uname)
ARCH=$(uname -m)
FPM=`which fpm` 2>/dev/null
CONFIG=Release
NAME=libmsquic
CONFLICTS=
DESCRIPTION="Microsoft implementation of the IETF QUIC protocol"
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

# process arguments and allow to override default values
while :; do
    if [ $# -le 0 ]; then
        break
    fi

    lowerI="$(echo $1 | tr "[:upper:]" "[:lower:]")"
    case $lowerI in
         -?|-h|--help)
            usage
            exit 1
            ;;
        -d|-debug|--debug)
            CONFIG=Debug
            ;;
        -config|--config)
            shift
            CONFIG=$1
            ;;
        -o|-output|--output)
            shift
            OUTPUT=$1
            ;;
        *)
            echo unknown argument
            ;;
    esac

    shift
done

if [ ${CONFIG} != 'Release' ]; then
  NAME=libmsquic-debug
  CONFLICTS='--conflicts libmsquic'
else
  CONFLICTS='--conflicts libmsquic-debug'
fi

ARTIFACTS="artifacts/bin/${OS}/${ARCH}_${CONFIG}_openssl"
if [ ! -e "$ARTIFACTS/libmsquic.so" ]; then
    echo "$ARTIFACTS/libmsquic.so" does not exist. Run build first.
    exit 1
fi

if [ -z ${OUTPUT} ]; then
    OUTPUT="artifacts/packages/${OS}/${ARCH}_${CONFIG}_openssl"
fi

mkdir -p ${OUTPUT}

# RedHat/CentOS
fpm -f -s dir -t rpm  -n ${NAME} -v ${VER_MAJOR}.${VER_MINOR}.${VER_PATCH} --license MIT --url https://github.com/microsoft/msquic \
    --package "$OUTPUT" --log error \
    --description "${DESCRIPTION}" \
    --provides libmsquic.so \
    ${CONFLICTS} \
    "$ARTIFACTS/libmsquic.so"=/usr/${LIBDIR}/libmsquic.so \
    "$ARTIFACTS/libmsquic.lttng.so"=/usr/${LIBDIR}/libmsquic.lttng.so

# Debian/Ubuntu
if [ "$LIBDIR" == 'lib64' ]; then
    LIBDIR="lib/x86_64-linux-gnu"
fi
fpm -f -s dir -t deb  -n ${NAME} -v ${VER_MAJOR}.${VER_MINOR}.${VER_PATCH} --license MIT --url https://github.com/microsoft/msquic \
    --package "$OUTPUT" --log error \
    --description "${DESCRIPTION}" \
    --provides libmsquic.so \
    ${CONFLICTS} \
    "$ARTIFACTS/libmsquic.so"=/usr/${LIBDIR}/libmsquic.so \
    "$ARTIFACTS/libmsquic.lttng.so"=/usr/${LIBDIR}/libmsquic.lttng.so
