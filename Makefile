.SHELL: /usr/bin/env bash

.PHONY: build

DOCKER ?= docker

GO_BUILD_IMAGE ?= golang:1.24.4-bookworm@sha256:ee7ff13d239350cc9b962c1bf371a60f3c32ee00eaaf0d0f0489713a87e51a67

build:
	$(DOCKER) run --rm \
		-v $(shell pwd):/source \
		-w /source \
		-e GOFLAGS="-buildvcs=false" \
		-e HOME=/tmp \
		--entrypoint /bin/bash \
		$(GO_BUILD_IMAGE) \
		-c "mkdir -p lib && go build -o ./lib/ip_filter.so -buildmode=c-shared ."
