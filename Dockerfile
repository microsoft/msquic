FROM 	martenseemann/quic-network-simulator-endpoint as source
RUN 	apt-get update -y \
	&& apt-get install -y \
		build-essential \
		cmake \
	&& apt-get clean
COPY 	. /src

FROM	source as build
WORKDIR /src/Debug
RUN	cmake -DQUIC_ENABLE_LOGGING=OFF -DQUIC_BUILD_TEST=OFF ..
RUN     cmake --build .
RUN 	openssl ecparam -out server.eckey -noout -name prime256v1 -genkey
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
COPY 	--from=source /src/run_endpoint.sh /run_endpoint.sh
COPY 	--from=build /src/Debug/server.* /
RUN 	chmod +x /run_endpoint.sh
ENTRYPOINT [ "/run_endpoint.sh" ]
