.PHONY: build test lint clean

default: build

build:
	go build -o build/dp-udp main.go

test:
	go test -v ./...

lint:
	golangci-lint run

clean:
	rm -rf build/
