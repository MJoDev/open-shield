# The stand-in application used by the quickstart stack.
FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
COPY examples/ ./examples/

RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
        -o /out/demo-backend ./examples/demo-backend

FROM alpine:3.21

RUN apk add --no-cache curl && adduser -D -u 10003 demo

COPY --from=build /out/demo-backend /usr/local/bin/demo-backend

USER demo
EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:3000/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/demo-backend"]
