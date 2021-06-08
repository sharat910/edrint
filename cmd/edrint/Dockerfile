FROM golang:1.16 as builder

RUN mkdir -p -m 0600 ~/.ssh && \
	ssh-keyscan bitbucket.org >> ~/.ssh/known_hosts && \
    git config --global url."git@bitbucket.org:".insteadOf https://bitbucket.org/

WORKDIR /app

RUN apt-get update && apt-get install libpcap-dev -y

COPY go.mod .
COPY go.sum .
# Get dependancies - will also be cached if we won't change mod/sum
RUN --mount=type=ssh go mod download
# COPY the source code as the last step
COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o edrint .
#RUN go build -o mlorch

FROM debian:buster-slim
RUN apt-get update && apt-get install tcpdump -y
WORKDIR /app/
COPY --from=builder /app/edrint .
CMD ["./edrint"]