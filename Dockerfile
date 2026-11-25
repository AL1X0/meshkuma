# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/meshwatch \
    ./cmd/meshwatch

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/meshwatch /usr/local/bin/meshwatch

ENTRYPOINT ["/usr/local/bin/meshwatch"]
CMD ["run", "--config", "/etc/meshwatch/config.yaml"]
