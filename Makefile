# Image URL to use all building/pushing image targets
IMG ?= cedar-webhook:latest
# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.31.1

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with finch.
# However, you may be able to replace this with docker
CONTAINER_TOOL ?= finch

FINCH_FEATURE ?= KIND_EXPERIMENTAL_PROVIDER=finch

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

##@ Demo

WEBHOOK_TARBALL = webhook.image.tar
KIND_NODE_IMG = cedar-kind-node:latest

# Once kind supports easily building node images with additional container images baked in, we'll just switch to that.
# https://github.com/kubernetes-sigs/kind/pull/3634
# We'll drop the node dockerfile and build the custom image in the `kind-image` target like:
#     kind build add-image cedar-webhook:latest --image cedar-kind-node:latest

KIND_NAME = cedar-cluster

.PHONY: kind-image
kind-image: image-build ## Build the kind node image
	$(CONTAINER_TOOL) image save $(IMG) -o scratch/$(WEBHOOK_TARBALL)
	$(CONTAINER_TOOL) build \
		-t $(KIND_NODE_IMG) \
		-f ./scratch/Dockerfile \
		--build-arg BASE_IMAGE=kindest/node:v$(ENVTEST_K8S_VERSION) \
		./scratch

.PHONY: kind
kind: kind-image ## Start a kind cluster configured to use the local authorization webhook
	$(FINCH_FEATURE) kind create cluster --config kind.yaml -v2
	kubectl apply -f config/crd/bases/cedar.k8s.aws_policies.yaml
	kubectl apply -f demo/authorization-policy.yaml
	kubectl apply -f demo/admission-policy.yaml
	# Create a kubeconfig for the authorizing webhoook to communicate with the API server
	$(CONTAINER_TOOL) exec -it $(KIND_NAME)-control-plane \
		/bin/sh -c '/usr/bin/kubeadm kubeconfig user \
		--org system:authorizers \
		--client-name system:authorizer:cedar-authorizer \
		--validity-period 744h > /cedar-authorizer/policies/cedar-kubeconfig.yaml'

.PHONY: clean-kind
clean-kind: ## Delete the kind cluster and clean up genereated files
	$(FINCH_FEATURE) kind delete cluster --name $(KIND_NAME)
	rm \
		./mount/policies/cedar-kubeconfig.yaml \
		./mount/*-user-kubeconfig.yaml \
		./mount/logs/kube-apiserver-audit* \
		./mount/certs/cedar-authorizer-server.* \
		./scratch/webhook.image.tar

.PHONY: sample-user-kubeconfig
sample-user-kubeconfig: mount/sample-user-kubeconfig.yaml ## Create a user 'sample-user' in the groups 'sample-group' and 'requires-labels'

mount/sample-user-kubeconfig.yaml:
	# Create a sample user kubeconfig so devs have an alternate identity to test things with
	$(CONTAINER_TOOL) exec -it $(KIND_NAME)-control-plane \
		/bin/sh -c '/usr/bin/kubeadm kubeconfig user \
		--org sample-group \
		--org requires-labels \
		--client-name sample-user \
		--validity-period 744h > /cedar-authorizer/sample-user-kubeconfig.yaml'
	# Set the sample user kubeconfig's server URL to something useable from the developer's desktop
	kubectl --kubeconfig ./mount/sample-user-kubeconfig.yaml config set clusters.kubernetes.server $(shell kubectl config view --minify -o jsonpath="{.clusters[0].cluster.server}")

.PHONY: sample-user-exercise
sample-user-exercise: mount/sample-user-kubeconfig.yaml admission-webhook 
	kubectl get cm --show-labels
	KUBECONFIG=./mount/sample-user-kubeconfig.yaml kubectl get cm -l owner=sample-user --show-labels
	KUBECONFIG=./mount/sample-user-kubeconfig.yaml kubectl create cm sample-config --from-literal=k1=v1

.PHONY: test-user-kubeconfig
test-user-kubeconfig: ## Create a user 'test-user' in the groups 'test-group' and 'viewers'
	# Create a test user kubeconfig so devs have an alternate identity to test things with
	$(CONTAINER_TOOL) exec -it $(KIND_NAME)-control-plane \
		/bin/sh -c '/usr/bin/kubeadm kubeconfig user \
		--org test-group \
		--org viewers \
		--client-name test-user \
		--validity-period 744h > /cedar-authorizer/test-user-kubeconfig.yaml'
	# Set the test user kubeconfig's server URL to something useable from the developer's desktop
	kubectl --kubeconfig ./mount/test-user-kubeconfig.yaml config set clusters.kubernetes.server $(shell kubectl config view --minify -o jsonpath="{.clusters[0].cluster.server}")


BASE64_VERSION=$(shell base64 --version 2>&1 | grep -c 'GNU coreutils')
ifneq ($(BASE64_VERSION),0)
    BASE64ARGS=-w 0
endif

.PHONY: admission-webhook
admission-webhook: ## Install the Cedar validatingwebhookconfiguration
	cat manifests/admission-webhook.yaml | \
		sed -e "s/CA_BUNDLE_CONTENT/$(shell cat mount/certs/cedar-authorizer-server.crt | base64 $(BASE64ARGS))/" | \
		kubectl apply -f -

##@ Cedar Schema

SCHEMA_DIR = cedarschema

$(SCHEMA_DIR):
	mkdir -p $(SCHEMA_DIR)

RAW_CEDAR_SCHEMA=scratch/raw-generated.cedarschema
K8S_CEDAR_SCHEMA=$(SCHEMA_DIR)/k8s-full.cedarschema
K8S_JSON_SCHEMA=$(K8S_CEDAR_SCHEMA).json

.PHONY: full-cedarschema
full-cedarschema: $(SCHEMA_DIR) ## Create combined admission and authorization cedarschema in both cedar and json formats
	./bin/schema-generator -output ./$(K8S_JSON_SCHEMA) -v 5
	cedar translate-schema \
		--direction json-to-cedar \
		-s $(K8S_JSON_SCHEMA) > $(RAW_CEDAR_SCHEMA)
	./bin/schema-formatter ./$(RAW_CEDAR_SCHEMA) > $(K8S_CEDAR_SCHEMA)
	rm $(RAW_CEDAR_SCHEMA)

K8S_AUTHZ_CEDAR_SCHEMA=$(SCHEMA_DIR)/k8s-authorization.cedarschema
K8S_AUTHZ_JSON_SCHEMA=$(K8S_AUTHZ_CEDAR_SCHEMA).json

.PHONY: authz-cedarschema
authz-cedarschema: $(SCHEMA_DIR) ## Create authorization cedarschema in both cedar and json formats
	./bin/schema-generator -admission=false -output ./$(K8S_AUTHZ_JSON_SCHEMA) -v 5
	cedar translate-schema \
		--direction json-to-cedar \
		-s $(K8S_AUTHZ_JSON_SCHEMA) > $(RAW_CEDAR_SCHEMA)
	./bin/schema-formatter ./$(RAW_CEDAR_SCHEMA) > $(K8S_AUTHZ_CEDAR_SCHEMA)
	rm $(RAW_CEDAR_SCHEMA)

.PHONY: cedarschemas
cedarschemas: build authz-cedarschema full-cedarschema ## Create all schemas

##@ Cedar policies

.PHONY: format-policies
format-policies: ## Format all cedar policies in the repository. Does not apply to policies in CRDs
	for file in $(shell find . -name '*.cedar'); do \
		echo $$file; \
		cedar format  -w -p $$file; \
	done

.PHONY: validate-policies
validate-policies: ## Validate policies against the k8s-full cedarschema
	for file in $(shell find . -name '*.cedar'); do \
		echo $$file; \
		cedar validate --schema cedarschema/k8s-full.cedarschema -p $$file; \
	done


##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

# Utilize Kind or modify the e2e tests to load the image locally, enabling compatibility with other vendors.
.PHONY: test-e2e  # Run the e2e tests against a Kind k8s instance that is spun up.
test-e2e:
	go test ./test/e2e/ -v -ginkgo.v

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter & yamllint
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build binaries.
	go build -o bin/cedar-webhook cmd/cedar-webhook/main.go
	go build -o bin/converter cmd/converter/main.go
	go build -o bin/schema-generator cmd/schema-generator/main.go
	go build -o bin/schema-formatter cmd/schema-formatter/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/cedar-webhook/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: image-build
image-build: ## Build container image with the webhook
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: image-push
image-push: ## Push container image with the webhook
	$(CONTAINER_TOOL) push ${IMG}

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name project-v3-builder
	$(CONTAINER_TOOL) buildx use project-v3-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm project-v3-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	@if [ -d "config/crd" ]; then \
		$(KUSTOMIZE) build config/crd > dist/install.yaml; \
	fi
	echo "---" >> dist/install.yaml  # Add a document separator before appending
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default >> dist/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: cert-manager
cert-manager: ## Install cert-manager in the cluster
	kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.16.0/cert-manager.yaml

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/webhook && $(KUSTOMIZE) edit set image webhook=${IMG}
	$(KUSTOMIZE) build config/default  | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUBECTL ?= kubectl
KUSTOMIZE ?= $(LOCALBIN)/kustomize-$(KUSTOMIZE_VERSION)
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen-$(CONTROLLER_TOOLS_VERSION)
ENVTEST ?= $(LOCALBIN)/setup-envtest-$(ENVTEST_VERSION)
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint-$(GOLANGCI_LINT_VERSION)

## Tool Versions
KUSTOMIZE_VERSION ?= v5.3.0
CONTROLLER_TOOLS_VERSION ?= v0.14.0
ENVTEST_VERSION ?= latest
GOLANGCI_LINT_VERSION ?= v1.54.2

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/cmd/golangci-lint,${GOLANGCI_LINT_VERSION})

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary (ideally with version)
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f $(1) ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv "$$(echo "$(1)" | sed "s/-$(3)$$//")" $(1) ;\
}
endef
