# Makefile for building and tagging the sandbox Docker image

.PHONY: help build tag print

# Overridable settings
IMAGE ?= happy-sandbox
REGISTRY ?=
DOCKER_CONTEXT ?= sandbox
DOCKERFILE ?= $(DOCKER_CONTEXT)/Dockerfile

# Default tag: git short SHA or 'dev'
TAG ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)

# Compute full image name (optionally prefixed by a registry)
ifeq ($(strip $(REGISTRY)),)
  FULL_IMAGE := $(IMAGE)
else
  FULL_IMAGE := $(REGISTRY)/$(IMAGE)
endif

help:
	@echo "Targets:"
	@echo "  build         Build image tagged :$(TAG) and :latest"
	@echo "  tag           Retag existing image (NEW_TAG=...)"
	@echo "Variables (overridable):"
	@echo "  IMAGE=$(IMAGE) REGISTRY=$(REGISTRY) TAG=$(TAG) DOCKER_CONTEXT=$(DOCKER_CONTEXT) DOCKERFILE=$(DOCKERFILE)"
	@echo "Examples:"
	@echo "  make build IMAGE=happy-sandbox TAG=v0.1.0"
	@echo "  make tag NEW_TAG=v0.1.0"

# Build the Docker image with both the computed TAG and 'latest'
build:
	docker build \
	  -f $(DOCKERFILE) \
	  -t $(FULL_IMAGE):$(TAG) \
	  -t $(FULL_IMAGE):latest \
	  $(DOCKER_CONTEXT)
	@$(MAKE) --no-print-directory print

# Retag an existing image to NEW_TAG (defaults: SRC_TAG=$(TAG))
SRC_TAG ?= $(TAG)
NEW_TAG ?= latest
tag:
	docker tag $(FULL_IMAGE):$(SRC_TAG) $(FULL_IMAGE):$(NEW_TAG)
	@$(MAKE) --no-print-directory print TAG=$(NEW_TAG)

print:
	@echo "Built image: $(FULL_IMAGE):$(TAG)"
	@echo "Also tagged: $(FULL_IMAGE):latest"
