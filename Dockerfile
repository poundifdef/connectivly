FROM golang:1.22 as builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY ./ ./
RUN go build connectivly
EXPOSE 3000
ENTRYPOINT ["./connectivly"]
