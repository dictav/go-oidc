all: lint test

lint:
	golangci-lint run

test:
	go test -race