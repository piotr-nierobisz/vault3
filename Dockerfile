# syntax=docker/dockerfile:1
#
# Production image for Vault3. Two binaries, one image:
#
#   vault3-web        the server (cmd/vault3)
#   vault3-scheduler  the background job process (cmd/scheduler)
#
# VAULT3_PROCESS picks which one runs, so the same image serves both roles
# and no deploy target has to override a start command. Default: web.
#
# The web binary is built with `bungo build`, not `go build`: that is what
# embeds web/layouts, web/views and web/static (the Argon2 wasm included)
# into the binary, so the runtime stage carries no web directory at all.

# ── Build ────────────────────────────────────────────────────────────────────
FROM golang:1.25-bookworm AS build

ENV CGO_ENABLED=0 GOFLAGS=-trimpath

WORKDIR /src

# Modules first: a source-only change reuses this layer.
COPY go.mod go.sum ./
RUN go mod download

# Pinned to the BunGo version go.mod requires — the CLI and the library must
# agree on the embedded-asset format.
RUN go install github.com/piotr-nierobisz/BunGo/cmd/bungo@v0.5.2

COPY . .

RUN bungo build --entry cmd/vault3/main.go --output /out/vault3-web \
 && go build -o /out/vault3-scheduler ./cmd/scheduler

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM alpine:3.21

# ca-certificates: the two outbound calls the app makes (Turnstile siteverify,
# the Mailgun API) are HTTPS. postgresql17-client: applying scripts/sql to the
# production database, which the app deliberately never does for itself.
RUN apk add --no-cache ca-certificates postgresql17-client \
 && adduser -D -H -u 10001 vault3

WORKDIR /app
COPY --from=build /out/vault3-web /out/vault3-scheduler /app/
# Not read at runtime in production (internal/runtime/runtime.go syncs the
# schema only when PRODUCTION_BOOL is false); they ride along so the one-time
# apply can be run from a shell in this container.
COPY scripts/sql /app/scripts/sql

USER vault3
EXPOSE 3403

ENTRYPOINT ["/bin/sh", "-c", "exec /app/vault3-${VAULT3_PROCESS:-web}"]
