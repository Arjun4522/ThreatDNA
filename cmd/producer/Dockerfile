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

# Build the producer application
RUN go build -o /usr/local/bin/producer ./cmd/producer

# Use a minimal image for the final stage
FROM alpine:latest

# Set the current working directory inside the container
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /usr/local/bin/producer /usr/local/bin/producer

# Copy the enterprise-attack.json file
COPY enterprise-attack.json /app/enterprise-attack.json

# Expose any necessary ports (if the producer has an API or serves anything)
# EXPOSE 8080

# Command to run the producer
ENTRYPOINT ["producer"]
