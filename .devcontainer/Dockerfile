FROM ghcr.io/microsoft/msquic/linux-build-xcomp@sha256:6cf1ae79dd1951d117d932402ffd35bcbe416f98471e456694bb48ab625945d6

ARG username=test
ARG useruid=1000
ARG usergid=${useruid}

RUN wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \
    && apt-get update -y \
    && apt-get install -y \
    # prepare-machine.ps1 needs dotnet
    dotnet-sdk-6.0 \
    # prep for perf command
    software-properties-common \
    # to connect from GitHub CLI
    openssh-server \
    && groupadd --gid ${usergid} ${username} \
    && useradd -s /bin/bash --uid ${useruid} --gid ${usergid} -m ${username} \
    && echo ${username} ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/${username} \
    && chmod 0440 /etc/sudoers.d/${username}

USER ${username}
