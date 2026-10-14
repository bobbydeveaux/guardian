# Base images come from mirror.gcr.io (Google's Docker Hub mirror) — Docker Hub
# rate limits (429) broke runs that built this action from source.

# ── Build stage ────────────────────────────────────────────────────────────────
FROM mirror.gcr.io/library/golang:alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY app/ .
RUN go build -o /guardian ./cmd/guardian

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM mirror.gcr.io/library/alpine:3.20

LABEL org.opencontainers.image.source="https://github.com/bobbydeveaux/guardian"

RUN apk add --no-cache git bash

COPY --from=builder /guardian /usr/local/bin/guardian
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
