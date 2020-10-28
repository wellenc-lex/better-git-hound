FROM golang:alpine

WORKDIR /app

COPY git-hound .

RUN go build -o main .

ENTRYPOINT ["./main"]