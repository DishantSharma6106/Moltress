#!/usr/bin/env bash
set -euo pipefail

for run in $(seq 1 50); do
  echo "verifier fuzz iteration ${run}"
  bpftool prog load bpf/out/kernelsentinel.bpf.o /sys/fs/bpf/kernelsentinel_fuzz type tracing || true
  bpftool prog dump xlated pinned /sys/fs/bpf/kernelsentinel_fuzz || true
  rm -f /sys/fs/bpf/kernelsentinel_fuzz || true
done

