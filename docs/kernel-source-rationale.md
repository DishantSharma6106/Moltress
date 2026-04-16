# Kernel Source Rationale

KernelSentinel is designed from Linux source locations that define the control points we are instrumenting or extending.

## Scheduler hot path

Sources consulted:

- https://github.com/torvalds/linux/blob/master/kernel/sched/fair.c
- https://github.com/torvalds/linux/blob/master/kernel/sched/core.c

Rationale:

- `pick_next_task_fair()` in `fair.c` is where the fair-class runnable entity selection happens, so it is the right fentry surface for latency-sensitive queue visibility.
- `__schedule()` in `core.c` is the global context-switch transition point, so it is the canonical scheduling boundary for runqueue delay correlation.
- `try_to_wake_up()` in `core.c` is the wakeup admission path; capturing it lets userspace derive wakeup-to-run latency without `/proc`.
- The design keeps scheduler instrumentation split between `fentry`, tracepoints, and raw tracepoints so we can preserve both semantic richness and lowest-latency event capture.

Design consequences:

- keep per-task scheduling state in bounded maps
- compute percentiles from histograms, not per-event userland joins
- avoid heavy map types in the wakeup fast path

## BPF verifier constraints

Source consulted:

- https://github.com/torvalds/linux/blob/master/kernel/bpf/verifier.c

Rationale:

- The verifier performs path-sensitive state analysis and explicitly enforces instruction and state-explosion limits.
- `check_struct_ops_btf_id()` also shows that `struct_ops` programs require GPL-compatible licensing and attach-time BTF validation.

Design consequences:

- keep each program small and split composable logic with `PROG_ARRAY` tail calls
- no unbounded loops
- fixed-size, verifier-friendly stack and map access patterns
- userspace feature-gates `struct_ops` loading by kernel capability

## XDP redirect and packet steering

Sources consulted:

- https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/intel/ixgbe/ixgbe_main.c
- https://github.com/torvalds/linux/blob/master/kernel/bpf/devmap.c
- https://github.com/torvalds/linux/blob/master/kernel/bpf/cpumap.c

Rationale:

- The driver receive path is where XDP programs execute before SKB allocation; that is the right plane for sub-microsecond drops and redirects.
- `dev_map_redirect()` in `devmap.c` feeds `__bpf_xdp_redirect_map()`, which is why the repo treats `DEVMAP` as the first-class redirection backend.
- `devmap` bulk queues and `cpumap` handoff semantics motivate keeping conntrack state local and compact in the XDP path.

Design consequences:

- XDP fast path uses `LRU_PERCPU_HASH` conntrack
- redirect decisions are map-driven
- TC is reserved for container-aware policy and byte accounting after the XDP gate

## LSM enforcement

Source consulted:

- https://github.com/torvalds/linux/blob/master/security/security.c

Rationale:

- `security_file_open()` dispatches the `file_open` hook.
- `security_socket_connect()` dispatches the `socket_connect` hook.
- `security_task_fix_setuid()` dispatches the `task_fix_setuid` hook.
- `security_file_ioctl()` is a stable audit surface for suspicious control-plane operations relevant to rootkit heuristics.

Design consequences:

- file, socket, and setuid policy maps are first-class pinned objects
- path-oriented policy is compiled into inode-aware rules where possible to avoid string-heavy verifier pain
- security audit events stream through dedicated ring buffers

## io_uring

Source consulted:

- https://github.com/torvalds/linux/blob/master/io_uring/io_uring.c

Rationale:

- `io_submit_sqes`, `io_issue_sqe`, and `io_complete_rw` are the key submission, issue, and completion boundaries for latency accounting.

Design consequences:

- per-opcode histograms are maintained in `PERCPU_ARRAY`
- completion events are correlated with scheduler delay via shared per-task stats
- stalled CQ drain alerts are emitted from userspace when ring watermark deltas stop progressing

## Memory management

Sources consulted:

- https://github.com/torvalds/linux/blob/master/mm/page_alloc.c
- https://github.com/torvalds/linux/blob/master/mm/oom_kill.c
- architecture-specific fault handling paths under `arch/*/mm/`

Rationale:

- allocation slow paths and OOM selection are better observability anchors than procfs sampling.
- page fault entry symbols differ by architecture and kernel version, so the implementation deliberately keeps attach targets variant-driven in userspace.

Design consequences:

- use kprobe variant selection for fault hooks
- correlate pressure from allocator failures, OOM activity, and page allocation tracepoints in BPF maps first
- keep the predictive pressure model in userspace so BPF remains bounded

## Userspace memory correlation

glibc does not provide a general-purpose USDT surface for `malloc` and `free`. For that reason the implementation uses `uprobe` and `uretprobe` attachment to libc symbols instead of fictional USDT markers.

