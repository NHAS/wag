# syntax=docker/dockerfile:1

# hadolint ignore=DL3007
FROM golang:latest AS builder

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    make wget llvm clang gcc git npm gulp libpam0g-dev && \
    ln -s "/usr/include/$(uname -m)-linux-gnu/asm" /usr/include/asm

WORKDIR /app
COPY . .
RUN make release

# hadolint ignore=DL3007
FROM redhat/ubi9-minimal:latest

# hadolint ignore=DL3041
RUN microdnf update -y && \
    microdnf install -y iptables nc pam && \
    microdnf clean all

WORKDIR /app/wag

COPY --from=builder /app/wag /usr/bin/wag
COPY --chmod=0777 docker_entrypoint.sh /

VOLUME /data
VOLUME /cfg

CMD ["/docker_entrypoint.sh"]
