# syntax=docker/dockerfile:1

# ---- build ---------------------------------------------------------------
FROM golang:1.24-alpine AS build
WORKDIR /src

# Download modules in their own layer so code changes don't re-download them.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
# CGO off => fully static binary that runs on a distroless/scratch base.
# -trimpath and -s -w strip local paths and debug symbols from the binary.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api

# ---- run -----------------------------------------------------------------
# Distroless static: no shell, no package manager, CA certs + tzdata only.
# Tiny attack surface, and the :nonroot tag runs as UID 65532.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/api /api
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/api"]
