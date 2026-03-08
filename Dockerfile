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

COPY --from=builder /bin/netwatch-agent /usr/local/bin/netwatch-agent

ENTRYPOINT ["/usr/local/bin/netwatch-agent"]
