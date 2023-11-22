# Copyright 2019 HAProxy Technologies LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM --platform=${BUILDPLATFORM} golang:1.21 AS builder

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

ARG GOOS=$TARGETOS
ARG GOARCH=$TARGETARCH

WORKDIR /go/src/github.com/haproxytech/kubernetes-ingress

RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt install --no-install-recommends -y git && \
    rm -rf /var/lib/apt/lists/*

RUN --mount=type=bind,target=/go/src/github.com/haproxytech/kubernetes-ingress/go.mod,src=./go.mod \
    --mount=type=bind,target=/go/src/github.com/haproxytech/kubernetes-ingress/go.sum,src=./go.sum \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

ENV CGO_ENABLED=0
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p /var/run/vars && \
    git config --get remote.origin.url > /var/run/vars/GIT_REPO && \
    git rev-parse --short HEAD > /var/run/vars/GIT_HEAD_COMMIT && \
    git log -1 --date=format:"%Y/%m/%d %T" --format="%ad" > /var/run/vars/GIT_DATE_LAST_COMMIT && \
    git describe --abbrev=0 --tags > /var/run/vars/GIT_LAST_TAG && \
    git rev-parse --short $(cat /var/run/vars/GIT_LAST_TAG) > /var/run/vars/GIT_TAG_COMMIT && \
    git diff $(cat /var/run/vars/GIT_HEAD_COMMIT) $(cat /var/run/vars/GIT_TAG_COMMIT) --quiet > /var/run/vars/GIT_MODIFIED1 || echo '.dev' > /var/run/vars/GIT_MODIFIED1 && \
    git diff --quiet > /var/run/vars/GIT_MODIFIED2 || echo '.dirty' > /var/run/vars/GIT_MODIFIED2 && \
    cat /var/run/vars/GIT_MODIFIED1 /var/run/vars/GIT_MODIFIED2 | tr -d '\n' > /var/run/vars/GIT_MODIFIED && \
    GOARM="${TARGETVARIANT#v}" go build \
        -ldflags "-X pkg.version.GitRepo=$(cat /var/run/vars/GIT_REPO) -X pkg.version.GitTag=$(cat /var/run/vars/GIT_LAST_TAG) -X pkg.version.GitCommit=$(cat /var/run/vars/GIT_HEAD_COMMIT) -X pkg.version.GitDirty=$(cat /var/run/vars/GIT_MODIFIED) -X \"pkg.version.GitCommitDate=$(cat /var/run/vars/GIT_DATE_LAST_COMMIT)\"" \
        -o /go/haproxy-ingress-controller .

FROM haproxytech/haproxy-debian:2.9-dev10

ARG TARGETPLATFORM

ARG S6_OVERLAY_VERSION=2.2.0.3
ENV S6_OVERLAY_VERSION $S6_OVERLAY_VERSION
ENV S6_READ_ONLY_ROOT=1

COPY /fs /

RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt install --no-install-recommends -y socat openssl util-linux htop tzdata curl libcap2-bin && \
    rm -rf /var/lib/apt/lists/* && \
    rm -f /usr/local/bin/dataplaneapi /usr/bin/dataplaneapi && \
    chgrp -R haproxy /usr/local/etc/haproxy /run /var && \
    chmod -R ug+rwx /usr/local/etc/haproxy /run /var && \
    setcap 'cap_net_bind_service=+ep' /usr/local/sbin/haproxy && \
    case "${TARGETPLATFORM}" in \
        "linux/arm64")      S6_ARCH=aarch64     ;; \
        "linux/amd64")      S6_ARCH=amd64       ;; \
        "linux/arm/v6")     S6_ARCH=arm         ;; \
        "linux/arm/v7")     S6_ARCH=armhf       ;; \
        "linux/ppc64le")    S6_ARCH=ppc64le     ;; \
        "linux/386")        S6_ARCH=x86         ;; \
        *) echo "ARG TARGETPLATFORM undeclared" >&2 && exit 1 ;; \
    esac && \
    curl -sS -L -o /tmp/s6-overlay-installer "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${S6_ARCH}-installer" && \
    chmod +x /tmp/s6-overlay-installer && \
    /tmp/s6-overlay-installer / && \
    rm -f /tmp/s6-overlay-installer && \
    mkdir /var/run/s6 && \
    chown haproxy:haproxy /var/run/s6 && \
    chmod ug+rwx /var/run/s6 && \
    sed -i 's/ root / haproxy /g' /etc/s6/init/init-stage2-fixattrs.txt && \
    chmod ugo+x /etc/services.d/*/run /etc/cont-init.d/* && \
    rm -rf /var/lib/pebble

COPY --from=builder /go/haproxy-ingress-controller .

ENTRYPOINT ["/start.sh"]
