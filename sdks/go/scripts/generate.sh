#!/bin/sh
# Generate Go gRPC stubs from the proto file.
# Requires: protoc, protoc-gen-go, protoc-gen-go-grpc
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROTO="$SCRIPT_DIR/../../../proto/settled.v1.proto"
OUT="$SCRIPT_DIR/../client/proto"

mkdir -p "$OUT"
protoc \
  --go_out="$OUT" \
  --go_opt=paths=source_relative \
  --go-grpc_out="$OUT" \
  --go-grpc_opt=paths=source_relative \
  --proto_path="$(dirname "$PROTO")" \
  settled.v1.proto
echo "Generated Go stubs in $OUT"
