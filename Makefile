# Copyright 2020-2024 Daniel Weiner
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

PODMAN := $(shell command -v podman 2> /dev/null)

REGISTRY := docker.io
NAMESPACE := $(shell id -un)
IMAGE := arris-monitor
TAG := latest

all: build publish clean

build:
	@echo "Building image '$(IMAGE):$(TAG)'"
	$(PODMAN) build \
		-t $(IMAGE):$(TAG) \
		-t $(REGISTRY)/$(NAMESPACE)/$(IMAGE):$(TAG) \
		-f Containerfile \
		.
	@echo "Image '$(IMAGE):$(TAG)' built successfully"

publish: build
	@echo "Publishing image '$(IMAGE):$(TAG)' to '$(REGISTRY)/$(NAMESPACE)/$(IMAGE):$(TAG)'"
	$(PODMAN) push $(REGISTRY)/$(NAMESPACE)/$(IMAGE):$(TAG)
	@echo "Image '$(REGISTRY)/$(NAMESPACE)/$(IMAGE):$(TAG)' published successfully"

clean:
	@echo "Cleaning up"
	$(PODMAN) rmi $(IMAGE):$(TAG) $(REGISTRY)/$(NAMESPACE)/$(IMAGE):$(TAG)
	@echo "Cleanup complete"
