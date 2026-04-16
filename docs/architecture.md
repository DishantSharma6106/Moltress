# Architecture

## Planes

KernelSentinel is split into five cooperating planes:

1. observability
2. network enforcement
3. security enforcement
4. adaptive scheduler feedback
5. io_uring observability

## Data flow

1. BPF programs collect compact state in pinned maps and emit selected events through subsystem ring buffers.
2. The Rust daemon loads kernel-compatible program variants, consumes ring buffers, and snapshots map state.
3. The analytics engine computes percentiles and drift metrics from map data only.
4. The policy compiler turns JSON DSL into pinned map updates without daemon restart.
5. The Go TUI receives gRPC streams from the daemon and renders live state.

## Map topology

- `HASH` pinned maps hold global policy and low-rate metadata.
- `LRU_PERCPU_HASH` maps hold conntrack and hot task state where bounded eviction is acceptable.
- `PERCPU_ARRAY` maps hold hot-path counters, histograms, and scheduler heat.
- `RINGBUF` maps stream events by subsystem.
- `PROG_ARRAY` enables tail-call composition for oversized paths.
- `SOCKMAP` and `SOCKHASH` support socket enforcement and redirection.

## Compatibility strategy

- BPF objects are built as CO-RE and guarded with `bpf_core_type_exists()` and `bpf_core_field_exists()`.
- Userspace selects attach variants for symbols that are not stable across kernels.
- `struct_ops` scheduler augmentation is optional and only enabled on kernels that expose the required BTF and attach support.
- arena-backed shared memory is treated as a future-capability path, not a baseline requirement, because 5.15 through 6.8 compatibility is non-negotiable.

## Policy model

The JSON DSL is compiled into several concrete map update sets:

- inode-scoped file policies keyed by `uid + dev + ino`
- per-cgroup syscall allow-lists
- socket allow-lists keyed by address family, protocol, remote address, and port
- network quota rules keyed by cgroup id

## Operational model

- maps are pinned under `/sys/fs/bpf/kernelsentinel`
- program links are managed by the Rust daemon
- live policy reload is atomic at the map level
- userland scheduler hints are written back with `sched_setattr()` after daemon-side scoring

