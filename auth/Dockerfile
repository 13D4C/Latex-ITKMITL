# syntax=docker/dockerfile:1.7

# ---- Stage 1: build the Svelte SPA ----
FROM node:20-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY web/ ./
# vite.config.ts writes to ../internal/web/dist — make sure the path exists.
RUN mkdir -p ../internal/web/dist && npm run build

# ---- Stage 2: build the Go binary with the SPA embedded ----
FROM golang:1.25-alpine AS go
ENV GOTOOLCHAIN=local
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Pull the freshly-built SPA into the embed path.
COPY --from=web /src/internal/web/dist ./internal/web/dist
# Trimpath strips local file paths from the binary; ldflags drop DWARF for a
# smaller image. CGO off so we can use the distroless static base.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/overleaf-ldap-auth .

# ---- Stage 3: minimal runtime ----
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=go /out/overleaf-ldap-auth /app/overleaf-ldap-auth
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/overleaf-ldap-auth"]
