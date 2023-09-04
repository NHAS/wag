FROM golang:1.21 AS builder

RUN apt update && \
    apt install -y make gcc-multilib wget llvm clang gcc git npm gulp libbpf-dev libpam0g-dev


RUN ln -s /usr/include$(uname -m)-linux-gnu/asm /usr/include/asm 


WORKDIR /app
COPY . .
RUN make release

FROM redhat/ubi9-minimal:latest


RUN microdnf update -y && \ 
    microdnf install -y iptables nc pam

WORKDIR /app/wag

COPY --from=builder /app/wag /usr/bin/wag
COPY docker_entrypoint.sh /
RUN chmod +x /docker_entrypoint.sh /usr/bin/wag

VOLUME /data
VOLUME /cfg

CMD ["/docker_entrypoint.sh"]