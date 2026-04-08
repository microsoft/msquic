# Stage 1: Base image
FROM ubuntu:24.04@sha256:186072bba1b2f436cbb91ef2567abca677337cfc786c86e107d25b7072feef0c AS base

LABEL org.opencontainers.image.source=https://github.com/microsoft/msquic

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-c"]

RUN apt-get update && apt-get install --no-install-recommends -y \
    apt-transport-https \
    ca-certificates \
    gnupg \
    software-properties-common \
    wget && \
    wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null && \
    apt-add-repository 'deb https://apt.kitware.com/ubuntu/ jammy main' && \
    apt-add-repository ppa:lttng/stable-2.13 && \
    apt-get update && \
    apt-get install -y tzdata \
    build-essential \
    cmake \
    clang \
    git \
    make \
    sudo \
    lttng-tools \
    perl \
    nasm \
    ruby \
    ruby-dev \
    rpm \
    cppcheck \
    clang-tidy \
    gdb \
    liblttng-ust-dev \
    libssl-dev \
    libnuma-dev \
    liburing-dev \
    && rm -rf /var/lib/apt/lists/*

RUN gem install fpm
RUN wget -q https://launchpad.net/ubuntu/+archive/primary/+files/libicu72_72.1-3ubuntu3_amd64.deb \
    && dpkg -i ./libicu72_72.1-3ubuntu3_amd64.deb \
    && rm ./libicu72_72.1-3ubuntu3_amd64.deb \
    && wget -q https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
    sudo dpkg -i packages-microsoft-prod.deb && \
    sudo add-apt-repository universe && \
    sudo apt-get update -y && \
    sudo apt-get install -y \
        # INSTALL POWERSHELl
        powershell \
    && rm -rf /var/lib/apt/lists/*

RUN git config --global safe.directory '*'

# Stage 2: dependencies for cross-build.
FROM base AS cross-build

RUN apt-get update -y && apt-get install --no-install-recommends -y \
    gcc-arm-linux-gnueabihf \
    g++-arm-linux-gnueabihf \
    binutils-arm-linux-gnueabihf \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    binutils-aarch64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

RUN dpkg --add-architecture arm64 && \
    dpkg --add-architecture armhf

RUN sed -i '/^Types:/a Architectures: amd64' /etc/apt/sources.list.d/ubuntu.sources && \
    mv /etc/apt/sources.list /etc/apt/sources.list.int && \
    cat /etc/apt/sources.list.int | grep "^deb" | sed 's/deb /deb [arch=amd64] /g' > /etc/apt/sources.list && \
    rm /etc/apt/sources.list.int

RUN echo $' \n\
deb [arch=armhf,arm64] http://ports.ubuntu.com/ noble main restricted universe multiverse \n\
deb [arch=armhf,arm64] http://ports.ubuntu.com/ noble-updates main restricted universe multiverse \n\
deb [arch=armhf,arm64] http://ports.ubuntu.com/ noble-backports main restricted universe multiverse \n\
' > /etc/apt/sources.list.d/arm-cross-compile-sources.list

RUN apt-get update \
    && apt-get --no-install-recommends install -y \
    liblttng-ust-dev:arm64 \
    liblttng-ust-dev:armhf \
    libnuma-dev:arm64 \
    libnuma-dev:armhf \
    liburing-dev:arm64 \
    liburing-dev:armhf \
    && rm -rf /var/lib/apt/lists/*
