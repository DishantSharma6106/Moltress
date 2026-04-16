#!/usr/bin/env bash
set -euo pipefail

KERNELS=("5.15" "6.1" "6.6" "6.8")

for version in "${KERNELS[@]}"; do
  echo "==> testing kernel ${version}"
  virtme-run \
    --kimg "/var/lib/kernels/vmlinuz-${version}" \
    --rw \
    --script-sh "mount -t bpf bpf /sys/fs/bpf && cd /work && make gen && make build"
done

