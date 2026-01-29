FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /shadowai ./cmd/shadowai

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /shadowai /usr/local/bin/shadowai
COPY migrations/ /migrations/
EXPOSE 8080
CMD ["shadowai"]
