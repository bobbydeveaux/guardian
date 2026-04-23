# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:latest AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY app/ .
RUN go build -o /guardian ./cmd/guardian

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache git bash

COPY --from=builder /guardian /usr/local/bin/guardian
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
