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

# Build the search application
RUN go build -o /usr/local/bin/search ./cmd/search

# Use a minimal image for the final stage
FROM alpine:latest

# Set the current working directory inside the container
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /usr/local/bin/search /usr/local/bin/search

# Copy the internal threatdnacore package
COPY --from=builder /app/internal/threatdnacore /app/internal/threatdnacore

# Copy the threats.bleve directory


# Expose any necessary ports (if the search has an API or serves anything)
# EXPOSE 8080

# Command to run the search
ENTRYPOINT ["search"]
