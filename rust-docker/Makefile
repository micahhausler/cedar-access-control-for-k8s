
IMAGE=micahhausler/rust-authorizer:latest

.PHONY: build
build:
	finch build \
		-t ${IMAGE} \
		-f ./Dockerfile \
		..

run:
	finch run \
		-it \
		--rm \
		-p 8443:8443 \
		-v `pwd`/..:/opt \
		-w /opt \
		-e RUST_LOG=info \
		-e TLS_CERT_PATH=mount/certs/cedar-authorizer-server.crt \
		-e TLS_KEY_PATH=mount/certs/cedar-authorizer-server.key \
		${IMAGE}
