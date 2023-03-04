FROM debian:bullseye
RUN apt update -y
RUN apt upgrade -y
RUN apt install -y make wget llvm clang gcc git npm gulp libbpf-dev
RUN wget https://go.dev/dl/go1.19.4.linux-amd64.tar.gz
RUN rm -rf /usr/local/go && tar -C /usr/local -xzf go1.19.4.linux-amd64.tar.gz
ENV PATH="$PATH:/usr/local/go/bin"
RUN mkdir -p /build/
RUN chmod 777 /build/
WORKDIR /build
ADD build-wag.sh .
RUN chmod 777 build-wag.sh
ENTRYPOINT ["bash", "/build/build-wag.sh"]

