SHELL := /usr/bin/env bash

.PHONY: help setup deps build-bee2 test run clean

help:
	@echo "Available targets:"
	@echo "  make setup      - init submodules and build bee2 static library"
	@echo "  make test       - run full test suite"
	@echo "  make run        - run demo application"
	@echo "  make clean      - remove bee2 build artifacts"

deps:
	@command -v go >/dev/null || (echo "go not found" && exit 1)
	@command -v cmake >/dev/null || (echo "cmake not found" && exit 1)
	@command -v git >/dev/null || (echo "git not found" && exit 1)

setup: deps
	git submodule update --init --recursive
	bash scripts/build_bee2.sh

build-bee2:
	bash scripts/build_bee2.sh

test: build-bee2
	go test ./... -v -count=1

run: build-bee2
	go run ./cmd/demo

clean:
	rm -rf bee2/build
