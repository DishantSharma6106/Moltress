#!/usr/bin/env bash
set -euo pipefail

sysctl -w net.core.bpf_jit_enable=2
bpftool prog show
grep '^bpf_prog_' /proc/kallsyms || true

