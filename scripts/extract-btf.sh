#!/usr/bin/env bash
set -euo pipefail

mkdir -p bpf/include
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/include/vmlinux.h

if command -v pahole >/dev/null 2>&1; then
  mkdir -p bpf/out
  pahole --btf_encode_detached bpf/out/vmlinux.btf /sys/kernel/btf/vmlinux
fi

