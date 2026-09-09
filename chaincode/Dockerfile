FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o registrar_cc main.go

FROM alpine:latest
WORKDIR /app
RUN apk add --no-cache bash ca-certificates
COPY --from=builder /app/registrar_cc .

CMD ["./registrar_cc"]
