buildlinux:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o edrintlinux

ship: buildlinux
	scp edrintlinux mars4:~/edrint/