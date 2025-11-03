# syntax=docker/dockerfile:1.6

FROM golang:1.23-alpine AS builder

WORKDIR /src

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/control-plane ./cmd/control-plane

FROM alpine:3.20

WORKDIR /app

RUN addgroup -S anyproxy && adduser -S anyproxy -G anyproxy

COPY --from=builder /out/control-plane /app/control-plane

USER anyproxy:anyproxy

EXPOSE 8080

ENTRYPOINT ["/app/control-plane"]
