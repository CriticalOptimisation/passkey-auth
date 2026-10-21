# Container image of the service (docs/container.md). Build it with
# tools/image.sh, which fixes the time stamps and the BuildKit version: a plain
# `docker build` gives a working image, but not the published digest.

# Build stage: every input pinned; nothing variable enters the binary.
FROM golang:1.27.1@sha256:162be5298a40ed317005c8339c6de4d10d3eef336d66dc8e9259b03ab9d3a6d2 AS build
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
COPY web ./web
# Never with the e2e tag: the test routes stay out of the image.
RUN go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
      -o /out/passkey-auth ./cmd/passkey-auth \
 && mkdir /out/data /out/tmp

# Final stage: the binary and two empty directories, with owners and modes set
# here, never taken from the build stage or the checkout.
FROM scratch
ARG REVISION
LABEL org.opencontainers.image.source=https://github.com/CriticalOptimisation/passkey-auth \
      org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.licenses=Apache-2.0
COPY --from=build --chown=0:0 --chmod=0555 /out/passkey-auth /passkey-auth
COPY --from=build --chown=65532:65532 --chmod=0700 /out/data /data
COPY --from=build --chown=65532:65532 --chmod=0700 /out/tmp /tmp
USER 65532:65532
EXPOSE 8080 8081
ENTRYPOINT ["/passkey-auth"]

# --- Change History -------------------------------------------------------
# | PR     | Summary                                                       |
# |--------|---------------------------------------------------------------|
# | #15    | reproducible scratch image, non-root, fixed modes             |
# | #14    | expose the host listener, 8081                                |
