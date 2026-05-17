FROM golang:1.25-alpine AS builder

WORKDIR /app
RUN apk update --no-cache && \
    apk upgrade --no-cache && \
    apk add --no-cache make

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make

# FIXME(djnn): make this user configurable
EXPOSE 8080

ENTRYPOINT [ "/app/mic" ]
