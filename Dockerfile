# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM node:24-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm test && npm run build

FROM golang:1.27-alpine AS test
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=$GOPROXY
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked go mod download
COPY *.go ./
COPY cmd/ ./cmd/
COPY web/.keep ./web/.keep
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked --mount=type=cache,target=/root/.cache/go-build go test -race ./... && go vet ./...

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS backend
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=$GOPROXY
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked go mod download
COPY *.go ./
COPY cmd/ ./cmd/
COPY --from=frontend /src/web ./web
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /mail-harbor .
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /data-init ./cmd/data-init

FROM alpine:3.23
RUN apk add --no-cache ca-certificates tzdata && addgroup -g 10001 app && adduser -D -H -u 10001 -G app app && mkdir /data && chown app:app /data
COPY --from=backend /mail-harbor /usr/local/bin/mail-harbor
COPY --from=backend /data-init /usr/local/bin/data-init
COPY LICENSE docs/licenses/ /usr/share/doc/mail-harbor/
USER 10001:10001
ENV LISTEN_ADDR=:8080 DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/mail-harbor"]
