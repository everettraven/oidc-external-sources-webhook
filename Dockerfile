FROM golang:1.25

COPY . .

RUN go build -o webhook main.go

ENTRYPOINT [ "./webhook", "run" ]

