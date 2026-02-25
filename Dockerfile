FROM golang:1.22-alpine AS builder

RUN apk add --no-cache gcc musl-dev libpcap-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ENV CGO_ENABLED=1
RUN go build -o /bin/netwatch-agent ./cmd/agent

FROM alpine:3.20

# ca-certificates is required for HTTPS scanners (e.g., OSV).
# rpm is optional but enables host rpm-db parsing when mounted.
RUN apk add --no-cache libpcap ca-certificates rpm

ARG SYFT_VERSION=1.18.1
RUN wget -qO /tmp/syft.tgz "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
    && tar -xzf /tmp/syft.tgz -C /tmp \
    && mv /tmp/syft /usr/local/bin/syft \
    && chmod +x /usr/local/bin/syft \
    && rm -f /tmp/syft.tgz

COPY --from=builder /bin/netwatch-agent /usr/local/bin/netwatch-agent

ENTRYPOINT ["/usr/local/bin/netwatch-agent"]
