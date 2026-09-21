.PHONY: all
all: pivzavr

#
# pivzavr: build pivzavr binary locally for development
#
# The PKCS#11 module and the PC/SC library that pivzavr uses are loaded at run
# time with purego, so neither the build nor a cross build needs a C toolchain.
# For example: make GOOS=windows GOARCH=amd64
#
# CGO is forced off (CGO_ENABLED=0) because the PKCS#11 module and the PC/SC
# library are loaded at run time with purego. A build without cgo has every
# feature and needs no C toolchain, so the flag is set on every go command that
# compiles code below and cannot be overridden from the environment.
#
# GOOS and GOARCH select the platform to build for and default to the platform
# of the host.
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
# GOAMD64 selects the minimum AMD64 architecture level to target. v3 enables
# AVX2, BMI and other instructions available on Haswell (2013) and later CPUs.
# Override with e.g. make GOAMD64=v1 to build a baseline binary.
GOAMD64 ?= v3
# VERSION is the version that --version reports and that a release is named
# after. It defaults to the description of the current commit, such as
# v1.4.0-3-g1234abc, and can be overridden: make release VERSION=v1.5.0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo development)
# LDFLAGS stamps VERSION into the binary. The -X flag of the linker sets the
# value of a string variable of the main package at link time.
LDFLAGS = -X main.version=$(VERSION)
# FreeBSD needs a compiler flag for the fake C runtime of purego when it is
# built without cgo, which is what a cross build does; NetBSD is listed with the
# same requirement. See the support notes of the purego project.
GCFLAGS_freebsd = -gcflags=github.com/ebitengine/purego/internal/fakecgo=-std
GCFLAGS_netbsd = $(GCFLAGS_freebsd)
# BIN is the name the go command gives the binary it builds for GOOS: it
# appends .exe to a windows binary.
BIN = pivzavr$(if $(filter windows,$(GOOS)),.exe)
.PHONY: pivzavr
pivzavr:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) GOAMD64=$(GOAMD64) go build $(GCFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/pivzavr

#
# install: install pivzavr to $GOPATH/bin
#
.PHONY: install
install:
	CGO_ENABLED=0 go install -ldflags '$(LDFLAGS)' ./cmd/pivzavr

#
# release: build a possibly cross-compiled and compressed release binary
#
# A cross build needs no cross C toolchain, for example:
# make release GOOS=windows GOARCH=amd64
#
.PHONY: release
EXE = pivzavr-$(GOOS)-$(GOARCH)
release: pivzavr
	(\
	set -e ;\
	cp -f $(BIN) $(EXE) ;\
	gzip -f -9 $(EXE) ;\
	)


#
# test: run tests
#
# The build without cgo is checked first: the PKCS#11 module and the PC/SC
# library are loaded at run time, so a build that leaves cgo out has to work as
# well and has every feature.
#
.PHONY: test
test: pivzavr
	(\
	set -e ;\
	CGO_ENABLED=0 go build ./... ;\
	CGO_ENABLED=0 go vet ./... ;\
	CGO_ENABLED=0 go test -coverprofile=cover.out ./... ;\
	file pivzavr ;\
	./pivzavr --help 2> /dev/null ;\
	golangci-lint run ./... ;\
	govulncheck ./... ;\
	gosec ./... ;\
	)

#
# clean: remove locally built artifacts
#
.PHONY: clean
clean:
	rm -rf ./pivzavr* ./cover.out
