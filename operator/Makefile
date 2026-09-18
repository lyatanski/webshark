# Everything runs in docker, so that a machine with no Go toolchain can still
# build this. The caches live under ~/.cache/webshark-operator, owned by whoever
# runs make, which is why the container runs as them.

IMG     ?= ghcr.io/lyatanski/webshark-operator:latest
CLUSTER ?= webshark
CACHE   := $(HOME)/.cache/webshark-operator
GO       = docker run --rm -u $(shell id -u):$(shell id -g) \
             -e HOME=/tmp -e GOCACHE=/gocache -e GOMODCACHE=/gomod -e GOFLAGS=-buildvcs=false \
             -v $(CURDIR):/src -w /src -v $(CACHE)/gomod:/gomod -v $(CACHE)/gocache:/gocache \
             golang:alpine
HELM     = docker run --rm -v $(CURDIR)/..:/w -w /w alpine/helm
YQ       = docker run --rm -i mikefarah/yq

# Pinned, not @latest: controller-gen writes the files that `make generate`
# then asks git whether anything changed, so a new release of it turning up
# mid-week would read as a types change nobody made.
CONTROLLER_TOOLS_VERSION ?= v0.22.0
CONTROLLER_GEN = go run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

# The chart's ClusterRole is hand-written - controller-gen emits one flat role
# and the chart splits leader election out into a namespaced Role - so the two
# are compared by what they grant rather than line by line: every rule from
# both chart roles, with each list sorted so only the permissions differ.
RBAC_RULES = '[.] | map(select(.kind == "ClusterRole" or .kind == "Role").rules) | flatten \
                | map(.apiGroups |= sort | .resources |= sort | .verbs |= sort) \
                | sort_by(.apiGroups[0] + "/" + .resources[0])'

.PHONY: all generate test verify-rbac image kind clean
all: generate test verify-rbac image

## deepcopy, the CRDs and the RBAC role, all from the markers in the source -
## and the CRDs copied into the chart, which is where they are installed from
generate: | $(CACHE)
	$(GO) sh -c '$(CONTROLLER_GEN) \
	  object:headerFile=/dev/null paths=./api/... \
	  crd paths=./api/... output:crd:dir=config/crd \
	  rbac:roleName=webshark-operator paths=./... output:rbac:dir=config/rbac'
	cp config/crd/*.yaml ../charts/webshark-operator/crds/

## gofmt -l exits 0 whether or not it found anything, so its output is the test
test: | $(CACHE)
	$(GO) sh -c 'f=$$(gofmt -l .); [ -z "$$f" ] || { echo "not gofmt-ed:"; echo "$$f"; exit 1; }; \
	  go vet ./... && go test ./...'

## nothing regenerates the chart's roles, so this is what keeps them honest
## against the markers on the controllers
verify-rbac: | $(CACHE)
	$(HELM) template ws /w/charts/webshark-operator \
	  | $(YQ) ea -o=json $(RBAC_RULES) > $(CACHE)/chart-rbac.json
	$(YQ) ea -o=json $(RBAC_RULES) < config/rbac/role.yaml > $(CACHE)/marker-rbac.json
	diff -u $(CACHE)/marker-rbac.json $(CACHE)/chart-rbac.json \
	  && echo 'chart RBAC is in step with the markers'

image:
	docker build -t $(IMG) .

## build, load into a kind cluster and restart the operator there
kind: image
	kind load docker-image $(IMG) --name $(CLUSTER)
	kubectl --context kind-$(CLUSTER) -n webshark rollout restart deploy/ws-webshark-operator

$(CACHE):
	mkdir -p $(CACHE)/gomod $(CACHE)/gocache

clean:
	rm -rf $(CACHE)
