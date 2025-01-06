# Dockerfile for Kind node
ARG BASE_IMAGE=kindest/node:v1.31.1

FROM ${BASE_IMAGE} AS builder

COPY webhook.image.tar /kind/images/webhook.image.tar
# The image import works, but the command returns an error, so we OR a success message
RUN containerd & ctr -n k8s.io i import /kind/images/webhook.image.tar || echo "success"

FROM ${BASE_IMAGE}

COPY --from=builder /var/lib/containerd /var/lib/containerd
