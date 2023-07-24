FROM ubuntu:20.04@sha256:c9820a44b950956a790c354700c1166a7ec648bc0d215fa438d3a339812f1d01

LABEL org.opencontainers.image.source https://github.com/microsoft/msquic

ENV DEBIAN_FRONTEND=noninteractive

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

RUN cat /etc/apt/sources.list | grep "^deb" | sed 's/deb /deb [arch=amd64] /g' > /etc/apt/sources.list

COPY arm-cross-compile-sources.list /etc/apt/sources.list.d/

RUN apt-get update

RUN apt-get install --no-install-recommends -y liblttng-ust-dev:arm64 \
    liblttng-ust-dev:armhf \
    libssl-dev:arm64 \
    libssl-dev:armhf \
    libnuma-dev:arm64 \
    libnuma-dev:armhf \
    && rm -rf /var/lib/apt/lists/*

RUN git config --global safe.directory '*'

