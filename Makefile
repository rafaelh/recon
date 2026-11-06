# CGO_ENABLED=0 is set only where it is needed: -race requires cgo on Linux,
# so it must not be exported for the whole Makefile.
TARGETS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64

.PHONY: build dist test clean

build:
	CGO_ENABLED=0 go build -trimpath -o recon ./cmd/recon

dist:
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "dist/recon-$$os-$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "-s -w" -o dist/recon-$$os-$$arch ./cmd/recon || exit 1; \
	done

# The cross-target vet type-checks every target's files, so an untagged
# platform-specific call (such as golang.org/x/sys/unix) cannot break one
# supported OS or architecture unnoticed. It runs before the tests so that a
# failing test cannot hide it.
test:
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "vet $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go vet ./... || exit 1; \
	done
	go test -race ./...

clean:
	rm -rf recon dist
