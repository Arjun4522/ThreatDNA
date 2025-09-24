# Build the Go app
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the builder binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /builder cmd/builder/main.go

# Final stage
FROM alpine:latest

WORKDIR /app

# Copy the builder binary from the builder stage
COPY --from=builder /builder .

# Run the builder
CMD ["/app/builder"]