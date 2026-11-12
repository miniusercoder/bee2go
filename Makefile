SHELL := /usr/bin/env bash

.PHONY: help setup deps build-bee2 test test-c run clean

help:
	@echo "Доступные команды:"
	@echo "  make setup      - подготовить submodule и собрать bee2"
	@echo "  make build-bee2 - собрать bee2"
	@echo "  make test       - запустить Go-тесты"
	@echo "  make test-c     - запустить C-тесты bee2"
	@echo "  make run        - запустить демонстрационное приложение"
	@echo "  make clean      - удалить результаты сборки"

deps:
	@command -v go >/dev/null || (echo "go not found" && exit 1)
	@command -v cmake >/dev/null || (echo "cmake not found" && exit 1)
	@command -v git >/dev/null || (echo "git not found" && exit 1)
	@command -v patch >/dev/null || (echo "patch not found" && exit 1)

setup: deps
	git submodule update --init --recursive
	bash scripts/build_bee2.sh

build-bee2:
	bash scripts/build_bee2.sh

test-c: build-bee2
	ctest --test-dir build/bee2 --output-on-failure --no-tests=error

test: build-bee2
	go test ./... -v -count=1

run: build-bee2
	go run ./cmd/demo

clean:
	rm -rf build
