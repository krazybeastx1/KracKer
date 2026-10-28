# Convenience wrapper around the CMake build.
#
#   make            # configure + build
#   make test       # build + run unit tests (needs libgtest-dev)
#   make install    # install to $(PREFIX) (default /usr/local)
#   make distclean  # remove the build directory
#
# Anything CMake-specific can still be passed directly, e.g.
#   cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug

BUILD_DIR  ?= build
CMAKE      ?= cmake
BUILD_TYPE ?= Release
PREFIX     ?= /usr/local
JOBS       ?= $(shell nproc 2>/dev/null || echo 2)

.PHONY: all configure build test run install clean distclean

all: build

configure:
	$(CMAKE) -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE)

build: configure
	$(CMAKE) --build $(BUILD_DIR) -j $(JOBS)

test: build
	ctest --test-dir $(BUILD_DIR) --output-on-failure

run: build
	$(BUILD_DIR)/bin/KracKer

install: build
	$(CMAKE) --install $(BUILD_DIR) --prefix $(PREFIX)

clean:
	$(CMAKE) --build $(BUILD_DIR) --target clean

distclean:
	rm -rf $(BUILD_DIR)
