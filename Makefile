.PHONY: build test clean

BINARY_NAME := sentinel
BUILD_DIR   := build
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -ldflags="-s -w -X 'github.com/loudmumble/sentinel/cmd/sentinel/cmd.Version=$(VERSION)'" -o $(BUILD_DIR)/$(BINARY_NAME) .

test:
	go test ./cmd/... ./internal/... -count=1 -v

clean:
	rm -rf $(BUILD_DIR)
