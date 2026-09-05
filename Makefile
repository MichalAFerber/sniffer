CGO := CGO_ENABLED=0
VERSION ?= 0.1.0
GOFLAGS := -trimpath -ldflags "-s -w -X main.version=$(VERSION)"
OUT := dist
BIN := netmapd

.PHONY: all build test vet pi linux-amd64 windows darwin dist clean

all: test dist

build:
	$(CGO) go build $(GOFLAGS) -o $(BIN) ./cmd/netmapd

test:
	$(CGO) go test ./...

vet:
	$(CGO) go vet ./...

# Pi Zero 2W / Pi 3+: Cortex-A53, 64-bit Raspberry Pi OS
pi:
	$(CGO) GOOS=linux GOARCH=arm64 GOARM64=v8.0 go build $(GOFLAGS) -o $(OUT)/$(BIN)-linux-arm64 ./cmd/netmapd

linux-amd64:
	$(CGO) GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(OUT)/$(BIN)-linux-amd64 ./cmd/netmapd

windows:
	$(CGO) GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o $(OUT)/$(BIN).exe ./cmd/netmapd

darwin:
	$(CGO) GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -o $(OUT)/$(BIN)-darwin-arm64 ./cmd/netmapd

# Original Pi Zero / Pi 1 (32-bit ARMv6). Only if you still have one.
pi-v6:
	$(CGO) GOOS=linux GOARCH=arm GOARM=6 go build $(GOFLAGS) -o $(OUT)/$(BIN)-linux-armv6 ./cmd/netmapd

dist:
	mkdir -p $(OUT)
	$(MAKE) pi linux-amd64 windows darwin

clean:
	rm -rf $(OUT) $(BIN)
