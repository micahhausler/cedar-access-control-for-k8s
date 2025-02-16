#! /usr/bin/env bash
set -e

mkdir ../policies
cat << EOF > ../policies/test1.cedar
// test-user can get/list/watch pods at cluster scope
permit (
    principal,
    action in [k8s::Action::"get", k8s::Action::"list", k8s::Action::"watch"],
    resource is k8s::Resource
) when {
    principal.name == "test-user" &&
    resource.resource == "pods"
};

// forbid test-user to get/list/watch nodes
forbid (
    principal,
    action in [k8s::Action::"get", k8s::Action::"list", k8s::Action::"watch"],
    resource is k8s::Resource
) when {
    principal.name == "test-user" &&
    resource.resource == "nodes"
};
EOF

cd ..;
cargo build

echo "running server in background... run 'fg' to take control and kill"
RUST_LOG=TRACE ./target/debug/cedar-k8s-webhook &

curl -H "content-type: application/json" http://localhost:8443/authorize -d @scratch/no-opinion.sar.json -v |jq
curl -H "content-type: application/json" http://localhost:8443/authorize -d @scratch/deny.sar.json -v |jq
curl -H "content-type: application/json" http://localhost:8443/authorize -d @scratch/allow.sar.json -v |jq
