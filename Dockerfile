# Build the manager binary
FROM golang:1.24 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# :oldmanshakesfistatcloud:
# Amazon's internal networks block the Go module proxy, so for now we set to direct
ENV GOPROXY=direct
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY api/ api/
COPY cmd/ cmd/
COPY internal/ internal/

# Build
# the GOARCH has not a default value to allow the binary be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform. 
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o cedar-webhook cmd/cedar-webhook/main.go

# Use distroless as minimal base image to package the webhook binary
# Refer to https://github.com/aws/eks-distro-build-tooling/tree/main/eks-distro-base#minimal-variants for more details
FROM public.ecr.aws/eks-distro-build-tooling/eks-distro-minimal-base:latest-al23
WORKDIR /
# COPY --from=builder /workspace/manager .
COPY --from=builder /workspace/cedar-webhook .
USER 65532:65532

EXPOSE 10288
EXPOSE 10289

ENTRYPOINT ["/cedar-webhook"]
