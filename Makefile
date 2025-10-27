VGO=go # Set to vgo if building in Go 1.10
BINARY_NAME=ethsign
SRC_GOFILES := $(shell find . -name '*.go' -print)
.DELETE_ON_ERROR:

all: build test
test: deps
		$(VGO) test  ./... -cover -coverprofile=coverage.txt -covermode=atomic
ethsign: ${SRC_GOFILES}
		$(VGO) build -o ${BINARY_NAME} -ldflags "-X main.buildDate=`date -u +\"%Y-%m-%dT%H:%M:%SZ\"` -X main.buildVersion=$(BUILD_VERSION)" -tags=prod -v
build: ethsign
ethsign-linux-arm64: ${SRC_GOFILES}
		GOOS=linux GOARCH=arm64 $(VGO) build -o ${BINARY_NAME} -ldflags "-X main.buildDate=`date -u +\"%Y-%m-%dT%H:%M:%SZ\"` -X main.buildVersion=$(BUILD_VERSION)" -tags=prod -v
build-linux-arm64: ethsign-linux-arm64
clean: 
		$(VGO) clean
		rm -f ${BINARY_NAME}
		rm -f ${BINARY_NAME}-linux-arm64
deps:
		$(VGO) get
