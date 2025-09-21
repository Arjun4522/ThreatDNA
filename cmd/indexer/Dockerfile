# Use the official Golang image as a base
FROM golang:1.23-alpine AS builder

# Set the current working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the indexer application
RUN go build -o /usr/local/bin/indexer ./cmd/indexer

# Use a minimal image for the final stage
FROM alpine:latest

# Set the current working directory inside the container
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /usr/local/bin/indexer /usr/local/bin/indexer

# Copy the internal threatdnacore package
COPY --from=builder /app/internal/threatdnacore /app/internal/threatdnacore

# Copy the threats.bleve directory


# Expose any necessary ports (if the indexer has an API or serves anything)
# EXPOSE 8080

# Command to run the indexer
ENTRYPOINT ["indexer"]
