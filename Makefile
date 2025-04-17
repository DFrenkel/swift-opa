BINDIR ?= $(HOME)/bin

.PHONY: all
all: fmt lint test build

.PHONY: fmt
fmt:
	swift format format --parallel --recursive -i .

.PHONY: lint
lint:
	swift format lint --parallel --recursive .

.PHONY: test
test:
	mkdir -p .build/test-results
	swift test --xunit-output .build/test-results/junit.xml

.PHONY: build
build:
	swift build
	
.PHONY: build-release
build-release:
	swift build -c release

.PHONY: ensure-bindir
ensure-bindir:
ifeq ($(shell test -d "$(BINDIR)"; echo $$?),1)
	$(error BINDIR "$(BINDIR)" does not exist.)
endif

.PHONY: install-release
install-release: build-release ensure-bindir
	install $(shell swift build --show-bin-path -c release)/swift-rego-cli $(BINDIR)/

.PHONY: clean
clean:
	rm -rf .build

.PHONY: bench
bench:
	OPA_BENCHMARK=enabled swift package benchmark
