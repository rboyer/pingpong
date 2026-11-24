.PHONY: all
all: docker

.PHONY: static
static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -tags netgo -ldflags '-w' -o pingpong.linux.amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -a -tags netgo -ldflags '-w' -o pingpong.linux.arm64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -a -tags netgo -ldflags '-w' -o pingpong.darwin.amd64

.PHONY: docker
docker: static
	# docker build --no-cache -t rboyer/pingpong .
	docker build --platform linux/amd64,linux/arm64 --no-cache -t rboyer/pingpong .
