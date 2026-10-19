GO ?= go
.DEFAULT_GOAL := check
.PHONY: help check verify build

help:
	@printf '%s\n' 'make check' 'make verify' 'make build'

check:
	GOWORK=off $(GO) test -race ./...
	GOWORK=off $(GO) vet ./...

verify: check build

build:
	GOWORK=off $(GO) build ./...
