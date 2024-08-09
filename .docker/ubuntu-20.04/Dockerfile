# Stage 1: Base image
FROM ubuntu:20.04@sha256:f2034e7195f61334e6caff6ecf2e965f92d11e888309065da85ff50c617732b8 as base

LABEL org.opencontainers.image.source https://github.com/microsoft/msquic

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-c"]

RUN apt-get update && apt-get install --no-install-recommends -y \
    apt-transport-https \
    ca-certificates \
    gnupg \
    software-properties-common \
    wget && \
    wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null && \
    apt-add-repository 'deb https://apt.kitware.com/ubuntu/ focal main' && \
    apt-add-repository ppa:lttng/stable-2.13 && \
    apt-get update && apt-get install -y tzdata && apt-get install -y \
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
    && rm -rf /var/lib/apt/lists/*

RUN gem install --version 2.8.1 dotenv
RUN gem install fpm
RUN wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
    sudo dpkg -i packages-microsoft-prod.deb && \
    sudo add-apt-repository universe && \
    sudo apt-get update -y && \
    sudo apt-get install -y \
        # INSTALL POWERSHELl
        powershell \
        iproute2 iptables \
   && rm -rf /var/lib/apt/lists/*

RUN git config --global safe.directory '*'

RUN git clone https://github.com/microsoft/msquic /msquic && \
    cd /msquic && \
    pwsh ./scripts/prepare-machine.ps1 -Tls openssl && \
    pwsh ./scripts/build.ps1 -Config Release -Tls openssl
