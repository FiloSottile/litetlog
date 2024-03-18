FROM golang:1.22.1-alpine3.19 as build

WORKDIR /src

RUN apk add build-base

COPY go.mod go.sum ./
RUN go mod download

COPY ./ ./
RUN go install -trimpath ./cmd/spicy

FROM alpine:3.19.1

RUN apk add bash rclone rsync

COPY --from=build /go/bin/spicy /usr/local/bin/spicy
COPY cmd/apt-transport-tlog/update-bucket.sh /usr/local/bin/update-bucket.sh

CMD ["bash", "/usr/local/bin/update-bucket.sh"]
