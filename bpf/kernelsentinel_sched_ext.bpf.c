// SPDX-License-Identifier: GPL-2.0-only
#include "include/kernelsentinel/common.h"

char SCHED_EXT_LICENSE[] SEC("license") = "GPL";

#if __has_include(<scx/common.bpf.h>)
#include <scx/common.bpf.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, KS_MAX_PID_SLOTS);
	__type(key, __u32);
	__type(value, struct ks_pid_heat_slot);
} sched_ext_heat SEC(".maps");

s32 BPF_STRUCT_OPS(ks_scx_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	__u32 pid = BPF_CORE_READ(p, pid);
	__u32 slot_idx = ks_pid_slot(pid);
	struct ks_pid_heat_slot *slot = bpf_map_lookup_elem(&sched_ext_heat, &slot_idx);

	if (slot && slot->cache_residency_score > 0)
		return slot->last_cpu;

	return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, 0);
}

void BPF_STRUCT_OPS(ks_scx_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(ks_scx_running, struct task_struct *p)
{
	__u32 pid = BPF_CORE_READ(p, pid);
	__u32 slot_idx = ks_pid_slot(pid);
	struct ks_pid_heat_slot *slot = bpf_map_lookup_elem(&sched_ext_heat, &slot_idx);

	if (!slot)
		return;

	slot->pid = pid;
	slot->last_cpu = ks_cpu();
	slot->last_run_ns = ks_now_ns();
	if (slot->cache_residency_score < 100)
		slot->cache_residency_score++;
}

SEC(".struct_ops.link")
struct sched_ext_ops ks_scx_ops = {
	.select_cpu = (void *)ks_scx_select_cpu,
	.enqueue = (void *)ks_scx_enqueue,
	.running = (void *)ks_scx_running,
	.name = "kernelsentinel",
};
#endif
