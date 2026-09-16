.PHONY: all
all: pivzavr

#
# pivzavr: build pivzavr binary locally for development 
#
.PHONY: pivzavr
pivzavr:
	CGO_ENABLED=1 go build ./cmd/pivzavr

#
# install: install pivzavr to $GOPATH/bin
#
.PHONY: install
install:
	go install ./cmd/pivzavr

#
# release: build a possibly cross-compiled and compressed release binary
#
.PHONY: release
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
EXE = pivzavr-$(GOOS)-$(GOARCH)
release: pivzavr
	(\
	set -e ;\
	cp -f pivzavr $(EXE) ;\
	gzip -f -9 $(EXE) ;\
	)

#
# test: run tests
#
.PHONY: test
test: pivzavr
	(\
	set -e ;\
	go test -coverprofile=cover.out ./pkg/... ;\
	file pivzavr ;\
	./pivzavr --help 2> /dev/null ;\
	)

#
# clean: remove locally built artifacts
#
.PHONY: clean
clean:
	rm -rf ./pivzavr* ./cover.out
