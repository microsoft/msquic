FROM 	martenseemann/quic-network-simulator-endpoint as source
ENV	DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y \
	&& apt-get install -y \
		build-essential \
		cmake \
	&& apt-get clean
COPY 	. /src

FROM	source as build
WORKDIR /src/Debug
RUN scripts/install-powershell.sh
RUN pwsh scripts/prepare-machine.ps1
RUN pwsh scripts/build.ps1 -DisableTest
RUN openssl ecparam -out server.eckey -noout -name prime256v1 -genkey
RUN	openssl pkcs8 -topk8 -inform pem -in server.eckey -nocrypt \
		-out server.key
RUN	openssl req -batch -new -key server.key -days 9365 -nodes -x509 \
		-subj "/" -addext "subjectAltName = DNS:server" -out server.crt

FROM 	martenseemann/quic-network-simulator-endpoint
RUN 	apt-get update -y \
	&& apt-get install -y \
		libatomic1 \
	&& apt-get clean
COPY 	--from=build /src/Debug/bin/Release /bin
COPY 	--from=build /src/Debug/bin/Release/*.so /lib/x86_64-linux-gnu
COPY 	--from=source /src/scripts/run_endpoint.sh /run_endpoint.sh
COPY 	--from=build /src/Debug/server.* /
RUN 	chmod +x /run_endpoint.sh
ENTRYPOINT [ "/run_endpoint.sh" ]
