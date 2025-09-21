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

# Build the builder application
RUN go build -o /usr/local/bin/builder ./cmd/builder

# Use a minimal image for the final stage
FROM alpine:latest

# Set the current working directory inside the container
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /usr/local/bin/builder /usr/local/bin/builder

# Copy the internal threatdnacore package
COPY --from=builder /app/internal/threatdnacore /app/internal/threatdnacore

# Copy the enterprise-attack.json file
COPY enterprise-attack.json /app/enterprise-attack.json

# Copy the threats.bleve directory
COPY threats.bleve /app/threats.bleve
COPY data /app/data

# Expose any necessary ports (if the builder has an API or serves anything)
# EXPOSE 8080

# Command to run the builder
ENTRYPOINT ["builder"]
