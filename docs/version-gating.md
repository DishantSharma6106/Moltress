# Version Gating

KernelSentinel targets Linux 5.15 LTS through 6.8 as the baseline matrix and treats newer capabilities as opt-in overlays.

## Baseline assumptions

- CO-RE is mandatory, so `vmlinux` BTF is assumed available or injected in CI.
- hot-path state uses `PERCPU_ARRAY` or `LRU_PERCPU_HASH`, never unbounded dynamic structures.
- symbol attachments that vary by architecture or release are selected in userspace, not hard-coded into a single load plan.

## Feature gates

- `kprobe/do_page_fault` is loaded opportunistically; `handle_mm_fault` remains the cross-kernel fallback.
- `struct_ops` scheduler augmentation is only loaded when the target kernel exposes the required BTF and attach surfaces.
- `bpf_loop()` is intentionally avoided in the baseline objects so 5.15 remains viable; bounded straight-line logic is used instead.
- `BPF_MAP_TYPE_ARENA` is documented as a post-6.8 optimization path and is not part of the baseline load set.

## CI expectation

`scripts/vmtest.sh` is expected to validate four kernel families:

- 5.15
- 6.1
- 6.6
- 6.8

The pass criteria are:

- verifier acceptance
- successful CO-RE relocation
- pinned map creation
- program attach success
- bounded map size and ring buffer size checks
