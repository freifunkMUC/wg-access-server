### Build stage for the website frontend
FROM --platform=$BUILDPLATFORM node:26.10.0-bookworm AS website
WORKDIR /code
COPY ./website/package.json ./
COPY ./website/package-lock.json ./
RUN npm ci --no-audit --prefer-offline
COPY ./website/ ./
RUN npm run build

### Build stage for the website backend server
FROM golang:1.27.2-alpine AS server
RUN apk add --no-cache gcc musl-dev
WORKDIR /code
ENV CGO_ENABLED=1
ARG VERSION=development
ARG COMMIT="-"
COPY ./go.mod ./
COPY ./go.sum ./
RUN go mod download
RUN go mod verify
COPY ./proto/proto/ ./proto/proto/
COPY ./main.go ./main.go
COPY ./cmd/ ./cmd/
COPY ./internal/ ./internal/
COPY ./buildinfo/ ./buildinfo/
RUN echo "Using: Version: ${VERSION}, Commit: ${COMMIT}"
RUN go generate buildinfo/buildinfo.go
RUN go build -o wg-access-server

### Server
FROM alpine:3.24.2
RUN apk add --no-cache iptables ip6tables nftables wireguard-tools curl openssl
ENV WG_CONFIG="/config.yaml"
# An empty config file at the path above, so that the server starts on its
# defaults and the environment variables when no config file is mounted over
# it. Without the file, reading the configured path fails and the server
# refuses to start - which is what an operator wants for a path they typed
# themselves, but this path is the image's own.
RUN touch /config.yaml
ENV WG_STORAGE="sqlite3:///data/db.sqlite3"
# Keep the generated self-signed certificate on the data volume, otherwise a
# recreated container serves a new certificate and every browser warns again
ENV WG_HTTPS_CERT_FILE="/data/wg-access-server.crt"
ENV WG_HTTPS_KEY_FILE="/data/wg-access-server.key"
COPY --from=server /code/wg-access-server /usr/local/bin/wg-access-server
COPY --from=website /code/build /website/build
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || curl -fk https://localhost:8443/health || exit 1
CMD ["wg-access-server", "serve"]
