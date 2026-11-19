VERSION ?= 0.1.0
LDFLAGS := -s -w
AGENT_TARGETS := linux/amd64 linux/arm64 linux/386 darwin/arm64 darwin/amd64 windows/amd64

.PHONY: all build manager agent agents test run-manager run-agent docker clean

all: test build

build: manager agent

manager:
	CGO_ENABLED=1 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/warden-manager ./cmd/warden-manager

agent:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/warden-agent ./cmd/warden-agent

# Static agent binaries for every supported platform → dist/
agents:
	@for t in $(AGENT_TARGETS); do \
	  os=$${t%/*}; arch=$${t#*/}; ext=""; [ $$os = windows ] && ext=.exe; \
	  echo "building agent $$os/$$arch"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags="$(LDFLAGS)" -o dist/warden-agent-$$os-$$arch$$ext ./cmd/warden-agent || exit 1; \
	done

test:
	go vet ./...
	go test ./...

run-manager: manager
	./bin/warden-manager -c deploy/manager.yml

# Local agent against a local manager (password printed by the manager on first start)
run-agent: agent
	sudo WARDEN_MANAGER=127.0.0.1:1514 WARDEN_ENROLLMENT_PASSWORD=$$(cat data/enrollment-password.txt) \
	  WARDEN_STATE_DIR=$(CURDIR)/data/agent ./bin/warden-agent

docker:
	docker compose up -d --build

clean:
	rm -rf bin dist
