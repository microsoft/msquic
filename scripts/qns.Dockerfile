FROM    martenseemann/quic-network-simulator-endpoint@sha256:2ec0a19a54f4547f068a81afcb3e92251b8808934eb86e5cb6919d91c4958791 as source
ENV     DEBIAN_FRONTEND=noninteractive
RUN     apt-get update -y \
            && apt-get install -y ca-certificates gpg wget \
            && test -f /usr/share/doc/kitware-archive-keyring/copyright \
            || wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null \
            && echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ focal main' | tee /etc/apt/sources.list.d/kitware.list >/dev/null \
            && apt-get update -y \
            && test -f /usr/share/doc/kitware-archive-keyring/copyright \
            || rm /usr/share/keyrings/kitware-archive-keyring.gpg \
            && apt-get install -y kitware-archive-keyring \
            && apt-get install -y build-essential cmake liblttng-ust-dev libnuma-dev \
            && apt-get clean
COPY    . /src

FROM    source as build
WORKDIR /src/Debug
RUN     chmod +x /src/scripts/install-powershell-docker.sh
RUN     /src/scripts/install-powershell-docker.sh
ENV     PATH="/root/.dotnet/tools:${PATH}"
RUN     cmake -DQUIC_BUILD_TOOLS=on -DQUIC_ENABLE_LOGGING=on ..
RUN     cmake --build .

FROM    martenseemann/quic-network-simulator-endpoint@sha256:2ec0a19a54f4547f068a81afcb3e92251b8808934eb86e5cb6919d91c4958791
RUN     apt-get update -y \
            && apt-get install -y \
            libatomic1 \
            liblttng-ust-dev \
            lttng-tools \
            && apt-get clean
COPY    --from=build /src/Debug/bin/Release /bin
COPY    --from=build /src/Debug/bin/Release/*.so /lib/x86_64-linux-gnu/
COPY    --from=source /src/scripts/run_endpoint.sh /run_endpoint.sh
COPY    --from=source /src/src/manifest/clog.sidecar /clog.sidecar
COPY    --from=source /src/scripts/install-powershell-docker.sh \
            /install-powershell-docker.sh
RUN     chmod +x /install-powershell-docker.sh
RUN     /install-powershell-docker.sh
ENV     PATH="/root/.dotnet/tools:${PATH}"
RUN     chmod +x /run_endpoint.sh
ENTRYPOINT [ "/run_endpoint.sh" ]
