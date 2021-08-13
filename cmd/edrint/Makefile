buildlinux:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o edrintlinux

ship: buildlinux
	scp edrintlinux server:~/edrint/
	scp config.yaml server:~/edrint/

shipserver:
	go build
	scp edrint telescope-inline:~/edrint
	scp  config.yaml telescope-inline:~/edrint