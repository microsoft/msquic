# Stage 1: Base image
FROM ubuntu:26.04@sha256:651ba3fe3a830441e3deaf70fafac40d808a6bd2800a6f2c43130055159f23e6 AS base

LABEL org.opencontainers.image.source=https://github.com/microsoft/msquic

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-c"]

RUN source /etc/os-release \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
    apt-transport-https \
    ca-certificates \
    gnupg \
    software-properties-common \
    wget \
    && wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null \
    && apt-add-repository "deb https://apt.kitware.com/ubuntu/ ${VERSION_CODENAME} main" \
    && apt-get update \
    && apt-get install -y tzdata \
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
    libicu-dev \
    liblttng-ust-dev \
    libssl-dev \
    libnuma-dev \
    liburing-dev \
    && rm -rf /var/lib/apt/lists/*

RUN gem install fpm
RUN wget -q https://packages.microsoft.com/config/ubuntu/26.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && add-apt-repository universe \
    && apt-get update -y \
    && (apt-get install -y powershell || \
        (apt-get install -y curl \
        && POWERSHELL_VERSION=7.5.2 \
        && mkdir -p /opt/microsoft/powershell/7 \
        && curl -L -o /tmp/powershell-linux-x64.tar.gz "https://github.com/PowerShell/PowerShell/releases/download/v${POWERSHELL_VERSION}/powershell-${POWERSHELL_VERSION}-linux-x64.tar.gz" \
        && tar zxf /tmp/powershell-linux-x64.tar.gz -C /opt/microsoft/powershell/7 \
        && chmod +x /opt/microsoft/powershell/7/pwsh \
        && ln -sf /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh \
        && rm -f /tmp/powershell-linux-x64.tar.gz)) \
    && rm -rf /var/lib/apt/lists/*

RUN git config --global safe.directory '*'

# Stage 2: dependencies for cross-build.
FROM base AS cross-build

RUN apt-get update -y && apt-get install --no-install-recommends -y \
    libnl-3-dev \
    libnl-genl-3-dev \
    libnl-route-3-dev \
    zlib1g-dev \
    zlib1g \
    pkg-config \
    m4 \
    libpcap-dev \
    libelf-dev \
    libc6-dev-i386 \
    libxdp-dev \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

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

# For cross-compilation, we need amd64 packages from the default Ubuntu repos and
# ARM packages from ports.ubuntu.com. Restrict default sources to amd64.
RUN sed -i '/^Types:/a Architectures: amd64' /etc/apt/sources.list.d/ubuntu.sources && \
    mv /etc/apt/sources.list /etc/apt/sources.list.int && \
    cat /etc/apt/sources.list.int | grep "^deb" | sed 's/deb /deb [arch=amd64] /g' > /etc/apt/sources.list && \
    rm /etc/apt/sources.list.int

RUN source /etc/os-release \
    && printf '%s\n' \
    "deb [arch=armhf,arm64] http://ports.ubuntu.com/ubuntu-ports ${VERSION_CODENAME} main restricted universe multiverse" \
    "deb [arch=armhf,arm64] http://ports.ubuntu.com/ubuntu-ports ${VERSION_CODENAME}-updates main restricted universe multiverse" \
    "deb [arch=armhf,arm64] http://ports.ubuntu.com/ubuntu-ports ${VERSION_CODENAME}-backports main restricted universe multiverse" \
    "deb [arch=armhf,arm64] http://ports.ubuntu.com/ubuntu-ports ${VERSION_CODENAME}-security main restricted universe multiverse" \
    > /etc/apt/sources.list.d/arm-cross-compile-sources.list

RUN apt-get update \
    && apt-get --no-install-recommends install -y \
    liblttng-ust-dev:arm64 \
    liblttng-ust-dev:armhf \
    libssl-dev:arm64 \
    libssl-dev:armhf \
    libnuma-dev:arm64 \
    libnuma-dev:armhf \
    liburing-dev:arm64 \
    liburing-dev:armhf \
    && rm -rf /var/lib/apt/lists/*
