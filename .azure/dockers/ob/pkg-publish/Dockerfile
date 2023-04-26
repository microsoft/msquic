FROM ubuntu:latest

LABEL maintainer="huanyi"

COPY publish-packages.sh /usr/src/

RUN chmod 755 /usr/src/publish-packages.sh

WORKDIR /usr/src/

# Predefine tiemzone to workaround tzdata installation stuck
ENV TZ=America/Los_Angeles

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Install prerequisites
RUN apt-get update && apt-get install -y \
    curl \
    gnupg2

RUN curl http://tux-devrepo.corp.microsoft.com/keys/tux-devrepo.asc > tux-devrepo.asc; apt-key add tux-devrepo.asc

RUN echo "deb [arch=amd64] http://tux-devrepo.corp.microsoft.com/repos/tux-dev/ xenial main" | tee /etc/apt/sources.list.d/tuxdev.list

RUN apt-get update

RUN apt-get install azure-repoapi-client -y

RUN mkdir ~/.repoclient/

ENTRYPOINT ["./publish-packages.sh"]