FROM golang:1.25-alpine AS build
WORKDIR /app


COPY go.mod ./


COPY *.go ./


RUN go build -o fileserver

FROM alpine:latest
WORKDIR /app


COPY --from=build /app/fileserver /app/fileserver


RUN mkdir -p /app/static /app/files


COPY static /app/static
COPY .env /app/.env

EXPOSE 8080
CMD ["/app/fileserver"]