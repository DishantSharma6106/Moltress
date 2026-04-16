#!/usr/bin/env bash
set -euo pipefail

mkdir -p proto/gen/go proto/gen/rust

protoc \
  --proto_path=proto \
  --go_out=proto/gen/go \
  --go-grpc_out=proto/gen/go \
  proto/kernelsentinel.proto

