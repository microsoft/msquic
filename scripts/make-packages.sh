#!/bin/bash

usage()
{
    echo "Usage: $0 [-output <directory>] [-config Debug]"
    exit 1
}

OS=$(uname)
ARCH=$(uname -m)
PKGARCH=${ARCH}
FPM=`which fpm` 2>/dev/null
CONFIG=Release
NAME=libmsquic
CONFLICTS=
DESCRIPTION="Microsoft implementation of the IETF QUIC protocol"
VENDOR="Microsoft"
MAINTAINER="Microsoft QUIC Team <quicdev@microsoft.com>"
VER_MAJOR=$(cat ./src/inc/msquic.ver | grep 'define VER_MAJOR'| cut -d ' ' -f 3)
VER_MINOR=$(cat ./src/inc/msquic.ver | grep 'define VER_MINOR'| cut -d ' ' -f 3)
VER_PATCH=$(cat ./src/inc/msquic.ver | grep 'define VER_PATCH'| cut -d ' ' -f 3)

if [ -z "$FPM" ]; then
  echo Install 'fpm'
  exit 1
fi

if [ "$OS" == 'Linux' ]; then
    OS=linux
    LIBEXT=so
    if [ "$ARCH" == 'x86_64' ]; then
        ARCH='x64'
        LIBDIR="lib64"
    else
        LIBDIR="lib"
        if [ "$ARCH" == "aarch64" ]; then
            ARCH=arm64
        else
            if [ "$ARCH" == "armv7l" ]; then
                ARCH=arm
            else
                ARCH=x86
            fi
        fi
    fi
else
  if [ "$OS" == 'Darwin' ]; then
    OS=macos
    ARCH=x64
    LIBEXT=dylib
  else
    echo Only Linux and macOS packaging is supported at the moment.
    exit 1
  fi
fi

# process arguments and allow to override default values
while :; do
    if [ $# -le 0 ]; then
        break
    fi

    lowerI="$(echo $1 | tr "[:upper:]" "[:lower:]")"
    case $lowerI in
        -a|-arch|--arch)
            shift
            ARCH=$1
            if [ "$ARCH" == 'arm64' ]; then
                PKGARCH=aarch64
            fi
            if [ "$ARCH" == 'arm' ]; then
                PKGARCH=armhf
            fi
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
       -\?|-h|--help)
            usage
            exit 1
            ;;
        *)
            echo unknown argument
            ;;
    esac

    shift
done

if [ ${CONFIG} != 'Release' ]; then
  NAME=libmsquic-debug
  CONFLICTS='libmsquic'
else
  CONFLICTS='libmsquic-debug'
fi

ARTIFACTS="artifacts/bin/${OS}/${ARCH}_${CONFIG}_openssl"

if [ -z ${OUTPUT} ]; then
    OUTPUT="artifacts/packages/${OS}/${ARCH}_${CONFIG}_openssl"
fi

echo "ARCH=$ARCH PKGARCH=$PKGARCH ARTIFACTS=$ARTIFACTS"

mkdir -p ${OUTPUT}

if [ "$OS" == "linux" ]; then
  # RedHat/CentOS
  FILES="${ARTIFACTS}/libmsquic.${LIBEXT}.${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}=/usr/${LIBDIR}/libmsquic.${LIBEXT}.${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}"
  FILES="${FILES} ${ARTIFACTS}/libmsquic.${LIBEXT}.${VER_MAJOR}=/usr/${LIBDIR}/libmsquic.${LIBEXT}.${VER_MAJOR}"
  if [ -e "$ARTIFACTS/libmsquic.lttng.${LIBEXT}.${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}" ]; then
     FILES="${FILES} ${ARTIFACTS}/libmsquic.lttng.${LIBEXT}.${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}=/usr/${LIBDIR}/libmsquic.lttng.${LIBEXT}.${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}"
  fi
  fpm \
    --force \
    --input-type dir \
    --output-type rpm \
    --architecture ${PKGARCH} \
    --name ${NAME} \
    --provides ${NAME} \
    --conflicts ${CONFLICTS} \
    --version ${VER_MAJOR}.${VER_MINOR}.${VER_PATCH} \
    --description "${DESCRIPTION}" \
    --vendor "${VENDOR}" \
    --maintainer "${MAINTAINER}" \
    --package "${OUTPUT}" \
    --license MIT \
    --url https://github.com/microsoft/msquic \
    --log error \
    ${FILES}

  # Debian/Ubuntu
  if [ "$ARCH" == 'x64' ]; then
      LIBDIR="lib/x86_64-linux-gnu"
  fi
  if [ "$ARCH" == 'arm64' ];then
    LIBDIR="lib/aarch64-linux-gnu"
  fi
  if [ "$ARCH" == 'arm' ];then
    LIBDIR="lib/arm-linux-gnueabihf"
  fi

  FILES="${ARTIFACTS}/libmsquic.${LIBEXT}.${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}=/usr/${LIBDIR}/libmsquic.${LIBEXT}.${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}"
  FILES="${FILES} ${ARTIFACTS}/libmsquic.${LIBEXT}.${VER_MAJOR}=/usr/${LIBDIR}/libmsquic.${LIBEXT}.${VER_MAJOR}"
  if [ -e "$ARTIFACTS/libmsquic.lttng.${LIBEXT}.${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}" ]; then
     FILES="${FILES} ${ARTIFACTS}/libmsquic.lttng.${LIBEXT}.${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}=/usr/${LIBDIR}/libmsquic.lttng.${LIBEXT}.${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}"
  fi
  fpm \
    --force \
    --input-type dir \
    --output-type deb \
    --architecture ${PKGARCH} \
    --name ${NAME} \
    --provides ${NAME} \
    --conflicts ${CONFLICTS} \
    --depends "libssl1.1" \
    --version ${VER_MAJOR}.${VER_MINOR}.${VER_PATCH} \
    --description "${DESCRIPTION}" \
    --vendor "${VENDOR}" \
    --maintainer "${MAINTAINER}" \
    --package "${OUTPUT}" \
    --license MIT \
    --url https://github.com/microsoft/msquic \
    --log error \
    ${FILES}
fi

# macOS
if [ "$OS" == "macos" ]; then
  fpm \
    --force \
    --input-type dir \
    --output-type osxpkg \
    --name ${NAME} \
    --provides ${NAME} \
    --conflicts ${CONFLICTS} \
    --version ${VER_MAJOR}.${VER_MINOR}.${VER_PATCH} \
    --description "${DESCRIPTION}" \
    --vendor "${VENDOR}" \
    --maintainer "${MAINTAINER}" \
    --package "${OUTPUT}" \
    --license MIT \
    --url https://github.com/microsoft/msquic \
    --log error \
    "$ARTIFACTS/libmsquic.${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}.dylib"=/usr/local/lib/libmsquic.${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}.dylib
fi
