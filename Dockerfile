# Build stage
FROM golang:1.21-alpine AS build

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN go build -o fileserver .

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Copy binary from build stage
COPY --from=build /app/fileserver .

# Copy templates and static files
COPY templates ./templates
COPY static ./static

# Create files directory
RUN mkdir -p files

EXPOSE 8080

CMD ["./fileserver"]