FROM ghcr.io/microsoft/msquic/linux-build-xcomp

RUN wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \
    && apt-get update -y \
    && apt-get install -y \
    # prep for perf command
    software-properties-common \
    # to connect from GitHub CLI
    openssh-server
RUN pwsh -c './scripts/prepare-machine.ps1'
