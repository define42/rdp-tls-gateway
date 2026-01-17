FROM golang:1.25-alpine AS builder

WORKDIR /app


RUN apk add --no-cache \
    build-base \
    pkgconf libvirt-dev nmap \
    nodejs npm

RUN npm install -g typescript@5.5.4

# Enable static binary
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64


# Copy module files first (better caching)
COPY go.mod go.sum  ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download


# Copy source
COPY *.go ./
COPY internal internal
COPY static static
COPY ui ui
COPY tsconfig.json ./

RUN tsc -p tsconfig.json
# Build
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build -o remotegateway


# ---------- runtime stage ----------
#FROM scratch

#WORKDIR /app

# Copy binary
#COPY --from=builder /app/remotegateway /app/remotegateway

# TLS certs will be mounted
#EXPOSE 8443


ENTRYPOINT ["/app/remotegateway"]
