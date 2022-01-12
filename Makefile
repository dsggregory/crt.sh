VERSION=$(shell git describe --tags --always)
REPOSITORY=$(shell git config --get remote.origin.url)

all:
	go build -o crt.sh -ldflags "-X main.Version=${VERSION} -X main.Repository=${REPOSITORY}"