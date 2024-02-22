# Step 1: Build the binary in a builder stage
FROM golang:1.22 as builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod ./
# COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source code into the container
COPY ./ .

# Build the Go app
# RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o connectivly .
RUN go build connectivly .

# Step 2: Use a small base image and copy the binary from the builder stage
FROM alpine:latest  

# Add CA Certificates for TLS connections
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/connectivly .

# Command to run the executable
CMD ["/root/connectivly"]
