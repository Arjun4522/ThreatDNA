# Build the Go app
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the producer binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /producer cmd/producer/main.go

# Final stage
FROM alpine:latest

WORKDIR /app

# Copy the producer binary from the builder stage
COPY --from=builder /producer .

# Run the producer
CMD ["/app/producer"]
