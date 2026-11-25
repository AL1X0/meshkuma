# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS builder

ARG VERSION=v1.0.0
ARG COMMIT=dev
ARG BUILD_DATE=""

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X meshwatch/internal/version.Version=${VERSION} -X meshwatch/internal/version.Commit=${COMMIT} -X meshwatch/internal/version.BuildDate=${BUILD_DATE}" \
    -o /out/meshwatch \
    ./cmd/meshwatch

FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=v1.0.0
ARG COMMIT=dev
ARG BUILD_DATE=""
ARG COMMIT_MSG=""

LABEL org.opencontainers.image.source="https://github.com/AL1X0/meshkuma" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.title="${COMMIT_MSG}"

COPY --from=builder /out/meshwatch /usr/local/bin/meshwatch

ENTRYPOINT ["/usr/local/bin/meshwatch"]
CMD ["run", "--config", "/etc/meshwatch/config.yaml"]
