#!/usr/bin/env bash
set -euo pipefail

mkdir -p bpf/include
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/include/vmlinux.h

if command -v pahole >/dev/null 2>&1; then
  mkdir -p bpf/out
  if ! pahole --btf_encode_detached bpf/out/vmlinux.btf /sys/kernel/btf/vmlinux; then
    echo "warning: skipping detached BTF generation; pahole could not encode /sys/kernel/btf/vmlinux" >&2
  fi
fi
