FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /bin/netwatch-agent ./cmd/agent

FROM alpine:3.20

RUN adduser -D -g '' netwatch
USER netwatch

COPY --from=builder /bin/netwatch-agent /usr/local/bin/netwatch-agent

ENTRYPOINT ["/usr/local/bin/netwatch-agent"]
