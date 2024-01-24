FROM ubuntu:20.04@sha256:f2034e7195f61334e6caff6ecf2e965f92d11e888309065da85ff50c617732b8

LABEL org.opencontainers.image.source https://github.com/microsoft/msquic

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-c"]

RUN apt-get update && apt-get install --no-install-recommends -y apt-transport-https \
    ca-certificates \
    gnupg \
    software-properties-common \
    wget && \
    wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null && \
    apt-add-repository 'deb https://apt.kitware.com/ubuntu/ focal main' && \
    apt-add-repository ppa:lttng/stable-2.13 && \
    apt-get update && apt-get install -y tzdata && apt-get install -y \
    build-essential \
    gcc-arm-linux-gnueabihf \
    g++-arm-linux-gnueabihf \
    binutils-arm-linux-gnueabihf \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    binutils-aarch64-linux-gnu \
    cmake \
    clang \
    git \
    make \
    sudo \
    liblttng-ust-dev \
    lttng-tools \
    perl \
    nasm \
    ruby \
    ruby-dev \
    rpm \
    libssl-dev \
    libnuma-dev \
    cppcheck \
    clang-tidy \
    gdb \
  && rm -rf /var/lib/apt/lists/*

RUN gem install fpm

RUN wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
    sudo dpkg -i packages-microsoft-prod.deb && \
    sudo add-apt-repository universe && \
    sudo apt-get update -y && \
    sudo apt-get install -y \
        # INSTALL POWERSHELl
        powershell \
  && rm -rf /var/lib/apt/lists/*

RUN dpkg --add-architecture arm64
RUN dpkg --add-architecture armhf

RUN mv /etc/apt/sources.list /etc/apt/sources.list.int && \
    cat /etc/apt/sources.list.int | grep "^deb" | sed 's/deb /deb [arch=amd64] /g' > /etc/apt/sources.list && \
    rm /etc/apt/sources.list.int

RUN echo $' \n\
deb [arch=armhf,arm64] http://ports.ubuntu.com/ focal main restricted universe multiverse \n\
deb [arch=armhf,arm64] http://ports.ubuntu.com/ focal-updates main restricted universe multiverse \n\
deb [arch=armhf,arm64] http://ports.ubuntu.com/ focal-backports main restricted universe multiverse \n\
' > /etc/apt/sources.list.d/arm-cross-compile-sources.list

RUN apt-get update

RUN apt-get install --no-install-recommends -y liblttng-ust-dev:arm64 \
    liblttng-ust-dev:armhf \
    libssl-dev:arm64 \
    libssl-dev:armhf \
    libnuma-dev:arm64 \
    libnuma-dev:armhf \
    && rm -rf /var/lib/apt/lists/*

RUN git config --global safe.directory '*'

