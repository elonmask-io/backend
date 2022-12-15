FROM golang:1.19 as build-env

COPY . /app/
WORKDIR /app/

RUN go build -o backend .

FROM debian:stable

RUN apt update && \
    apt install ca-certificates -y

COPY --from=build-env --chown=root:root \
    /app/backend \
    /app/

EXPOSE 8080

ENTRYPOINT [ "/app/backend" ]