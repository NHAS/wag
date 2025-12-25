# syntax=docker/dockerfile:1

# hadolint ignore=DL3007
FROM golang:latest AS builder

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    make wget gcc git npm libpam0g-dev

WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    GOMODCACHE=/go/pkg/mod \
    GOCACHE=/root/.cache/go-build \
    make release

# hadolint ignore=DL3007
FROM redhat/ubi9-minimal:latest

# hadolint ignore=DL3041
RUN microdnf update -y && \
    microdnf install -y iptables nc pam && \
    microdnf clean all

WORKDIR /app/wag

COPY --from=builder /app/wag /usr/bin/wag
COPY --chmod=0770 docker_entrypoint.sh /

VOLUME /data
VOLUME /cfg

CMD ["/docker_entrypoint.sh"]
