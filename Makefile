.PHONY: lint

lint:
	GOWORK=off golangci-lint run ./...
