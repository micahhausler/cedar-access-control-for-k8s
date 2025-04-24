# Rust port of cedar authorizer

The rust port currently includes:
- [x] Authorizing Webhook
- [x] Access control admission webhook
- [x] Cedar Policy CRD validating admission webhook
- [x] Schema generator 
- [ ] RBAC Converter

## Build
```bash
cargo build
```


## Schema builder

```bash
RUST_BACKTRACE=full cargo run --bin k8s_schema  | jq -S --tab > output.json

# then to compare wtih go-generated cedar schema
cat cedarschema/k8s-full.cedarschema.json | jq --tab --sort-keys > formatted-cedarschema.json
vimdiff output.json formatted-cedarschema.json
```

