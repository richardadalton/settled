#!/bin/sh
# Regenerate Python gRPC stubs from the canonical proto.
#
# Requires: pip install grpcio-tools
#
# Two protoc quirks need handling at once:
#   1. Dots in the .proto filename are treated as path separators, so
#      generating from settled.v1.proto directly would emit
#      settled/v1_pb2.py. We use a dot-free alias settled_v1.proto.
#   2. The generated *_grpc.py emits a top-level "import settled_v1_pb2"
#      unless the proto is referenced via a package path. We stage the
#      proto under settled/proto/ and invoke protoc with a matching
#      proto_path so the import becomes "from settled.proto import ...".

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SDK_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROTO_SRC="$SDK_DIR/../../proto/settled.v1.proto"
OUT_DIR="$SDK_DIR/src"

if [ ! -f "$PROTO_SRC" ]; then
  echo "error: canonical proto not found at $PROTO_SRC" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/settled/proto"
cp "$PROTO_SRC" "$TMP/settled/proto/settled_v1.proto"

cd "$TMP"
python -m grpc_tools.protoc \
  -I. \
  --python_out="$OUT_DIR" \
  --grpc_python_out="$OUT_DIR" \
  settled/proto/settled_v1.proto

echo "Regenerated stubs in $OUT_DIR/settled/proto/"

