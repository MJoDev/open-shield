# open-shield dashboard — React application embedded in the Go API binary.
#
# One container serves both, so the SPA can never drift out of step with the API
# it calls, and the deployment has one fewer moving part.

# --- 1. Build the React application ------------------------------------------
FROM node:22-alpine AS web

WORKDIR /web
COPY dashboard/web/package.json dashboard/web/package-lock.json* ./
RUN npm ci --no-audit --no-fund

COPY dashboard/web/ ./
RUN npm run build

# --- 2. Build the Go binary with the application embedded --------------------
FROM golang:1.25-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY internal/ ./internal/
COPY dashboard/ ./dashboard/

# Replace the placeholder index.html with the real build before compiling: the
# embed directive reads whatever is on disk at compile time.
RUN rm -rf dashboard/api/web/dist
COPY --from=web /web/dist/ ./dashboard/api/web/dist/

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/dashboard-api ./dashboard/api/cmd/api

FROM alpine:3.21

RUN apk add --no-cache ca-certificates curl \
    && adduser -D -u 10002 openshield

COPY --from=build /out/dashboard-api /usr/local/bin/dashboard-api

USER openshield
EXPOSE 8081

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8081/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/dashboard-api"]
