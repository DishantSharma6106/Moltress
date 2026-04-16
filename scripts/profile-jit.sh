#!/usr/bin/env bash
set -euo pipefail

perf record -e cycles -a --call-graph dwarf -- sleep 10
perf report --stdio | grep bpf_prog_ || true

