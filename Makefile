#-------------------------------------------------------------------------------
# VARIABLES
#-------------------------------------------------------------------------------

NAME      = cbdynclusterd
DIST_NAME ?= $(NAME)
MAIN_PATH = github.com/couchbaselabs/cbdynclusterd

VERSION = $(shell git describe --always --tags)
GOFLAGS = -ldflags "-X ${MAIN_PATH}/daemon.Version=${VERSION}"

GOOS 	?= darwin
GOARCH  ?= amd64

#-------------------------------------------------------------------------------
# SPECIAL
#-------------------------------------------------------------------------------

.DEFAULT: default
.PHONY: default
default: clean submodule build

.PHONY: all
all: clean submodule build-all

.PHONY: release
release: clean submodule build-all

.PHONY: submodule
submodule:
	git submodule update --init --recursive

#-------------------------------------------------------------------------------
# EXECUTABLE
#-------------------------------------------------------------------------------

.PHONY: clean
clean:
	go clean .
	rm -rf bin

.PHONY: run
run:
	./bin/$(NAME).$(GOOS)_$(GOARCH)

.PHONY: install
install:
	cp bin/$(NAME).$(GOOS)_$(GOARCH) ~/bin/$(DIST_NAME)

#-------------------------------------------------------------------------------
# BUILD
#-------------------------------------------------------------------------------

.PHONY: build
build:
	$(GOENV) GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) -o bin/$(NAME).$(GOOS)_$(GOARCH)
	chmod +x bin/$(NAME).$(GOOS)_$(GOARCH)
.PHONY: build-all
build-all: build-mac build-linux

.PHONY: build-mac
build-mac: GOOS=darwin
build-mac:
	@$(MAKE) build GOOS=$(GOOS) GOARCH=$(GOARCH)

.PHONY: build-linux
build-linux: GOOS=linux
build-linux:
	@$(MAKE) build GOOS=$(GOOS) GOARCH=$(GOARCH)
