.PHONY: all
all: docker

.PHONY: static
static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -tags netgo -ldflags '-w'

.PHONY: docker
docker: static
	docker build --no-cache -t rboyer/pingpong .
