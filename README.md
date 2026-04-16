# Moltress

Moltress is the workspace for **KernelSentinel**, a kernel-native runtime intelligence layer built around eBPF CO-RE, libbpf, a Rust control daemon, and a Go TUI. The repo is structured to keep the kernel-facing logic verifier-friendly and the userspace logic safe, typed, and reloadable.

This first cut lays down the production-facing architecture and representative implementations for all five requested planes:

- observability
- network enforcement
- security enforcement
- adaptive scheduler feedback
- io_uring observability

## Why this layout

The design is anchored to actual Linux kernel source, not high-level documentation. The rationale is captured in [docs/kernel-source-rationale.md](docs/kernel-source-rationale.md) and the load strategy is captured in [docs/version-gating.md](docs/version-gating.md).

## Repo layout

- `bpf/`: CO-RE BPF programs and shared headers
- `daemon/`: Rust control plane, analytics engine, policy compiler, gRPC server
- `cli/`: Go Bubble Tea TUI
- `proto/`: gRPC API schema
- `xtask/`: build orchestration for BTF extraction, skeleton generation, CI checks
- `scripts/`: VM test harness, BTF validation, JIT profiling helpers
- `examples/`: policy DSL examples
- `deploy/`: systemd integration

## Toolchain prerequisites

The target toolchain for this repo is:

- `clang-17`
- `llvm-strip`
- `bpftool`
- `pahole`
- `cargo`
- `go`
- `protoc`
- `virtme-ng`

Those binaries are not installed in the current session, so the code here is scaffolded and source-backed, but not compiled in-session.

## Build flow

```bash
make gen
make build
make vmtest
```

`make gen` is expected to:

1. extract `vmlinux.h` from `/sys/kernel/btf/vmlinux`
2. build the CO-RE objects
3. generate the libbpf skeletons
4. generate Rust and Go gRPC bindings

## Current status

What is implemented in this repo now:

- pinned map architecture
- ring buffer event schema
- representative BPF hooks for all five planes
- stateful XDP conntrack layout using `LRU_PERCPU_HASH`
- BPF LSM policy surfaces
- optional `struct_ops` scheduler extension object
- Rust analytics and policy compiler skeleton
- Go TUI model and rendering skeleton
- CI and kernel-validation harness scripts

What still depends on the real toolchain and target kernels:

- generating `vmlinux.h`
- generating libbpf skeletons
- generating protobuf bindings
- compiling and verifier-testing the BPF objects
- loading program variants against 5.15, 6.1, 6.6, and 6.8 kernels

The Rust daemon currently defaults to `--stub-runtime=true` until the generated skeleton artifacts are present.
