### Build stage for the website frontend
FROM --platform=$BUILDPLATFORM node:24.8.0-bookworm AS website
WORKDIR /code
COPY ./website/package.json ./
COPY ./website/package-lock.json ./
RUN npm ci --no-audit --prefer-offline
COPY ./website/ ./
RUN npm run build

### Build stage for the website backend server
FROM golang:1.24.5-alpine AS server
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
COPY ./pkg/ ./pkg/
COPY ./internal/ ./internal/
COPY ./buildinfo/ ./buildinfo/
RUN echo "Using: Version: ${VERSION}, Commit: ${COMMIT}"
RUN go generate buildinfo/buildinfo.go
RUN go build -o wg-access-server

### Server
FROM alpine:3.22.2
RUN apk add --no-cache iptables ip6tables wireguard-tools curl openssl
ENV WG_CONFIG="/config.yaml"
ENV WG_STORAGE="sqlite3:///data/db.sqlite3"
COPY --from=server /code/wg-access-server /usr/local/bin/wg-access-server
COPY --from=website /code/build /website/build
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1
CMD ["wg-access-server", "serve"]
