# open-shield rules engine.
#
# The build context is the repository root: engine and dashboard share one Go
# module, so the whole tree has to be visible to the compiler.
FROM golang:1.25-alpine AS build

WORKDIR /src

# Dependencies first, so a source-only change does not re-download the module
# cache on every rebuild.
COPY go.mod go.sum ./
RUN go mod download

COPY internal/ ./internal/
COPY migrations/ ./migrations/
COPY engine/ ./engine/

ARG VERSION=dev
# CGO off gives a static binary, which is what lets the runtime stage be
# scratch-thin: no libc, no shell, nothing to exploit if the engine is ever
# reached.
RUN CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/engine ./engine/cmd/engine

FROM alpine:3.21

# curl backs the healthcheck; ca-certificates is there for a future outbound
# integration (RF-07 notifications).
RUN apk add --no-cache ca-certificates curl \
    && adduser -D -u 10001 openshield

COPY --from=build /out/engine /usr/local/bin/engine

USER openshield
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/readyz || exit 1

ENTRYPOINT ["/usr/local/bin/engine"]
