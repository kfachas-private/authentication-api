# syntax=docker/dockerfile:1
FROM golang:1.16-alpine

WORKDIR /server

COPY go.mod ./
COPY go.sum ./

RUN go mod download
COPY authentication-api ./

RUN go build -o /authentication-api

EXPOSE 9090

CMD [ "/authentication-api" ]