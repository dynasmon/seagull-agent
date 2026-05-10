FROM golang:1.25-alpine AS builder

RUN apk add --no-cache gcc musl-dev libpcap-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ENV CGO_ENABLED=1
RUN go build -buildvcs=false -o /bin/seagull-agent ./cmd/agent

FROM alpine:3.22

RUN apk add --no-cache libpcap ca-certificates rpm

COPY --from=builder /bin/seagull-agent /usr/local/bin/seagull-agent
COPY docker-entrypoint.sh /usr/local/bin/seagull-agent-entrypoint

RUN chmod +x /usr/local/bin/seagull-agent-entrypoint

ENTRYPOINT ["/usr/local/bin/seagull-agent-entrypoint"]
