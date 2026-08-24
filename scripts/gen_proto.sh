#!/usr/bin/env bash
# Regenerate gRPC stubs. Run from anywhere; writes next to the .proto file.
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-.venv/bin/python}"
"$PYTHON" -m grpc_tools.protoc \
  -I. \
  --python_out=. \
  --grpc_python_out=. \
  credbroker/proto/credbroker.proto
echo "generated credbroker/proto/credbroker_pb2.py and credbroker_pb2_grpc.py"
