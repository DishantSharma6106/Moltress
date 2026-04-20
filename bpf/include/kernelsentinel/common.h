#ifndef __KERNELSENTINEL_COMMON_H
#define __KERNELSENTINEL_COMMON_H

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Preprocessor constants not emitted into vmlinux.h (they are #defines, not enums). */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

#ifndef EPERM
#define EPERM 1
#endif

#ifndef EACCES
#define EACCES 13
#endif

#define KS_RINGBUF_SIZE (1U << 27)
#define KS_HIST_BUCKETS 32
#define KS_MAX_OPCODE 256
#define KS_MAX_PID_SLOTS 32768
#define KS_MAX_SYSCALL_WORDS 8
#define KS_TAIL_XDP_L4 0

typedef __u64 __attribute__((btf_type_tag("cgroup_id"))) ks_cgroup_id_t;
typedef __u64 __attribute__((btf_type_tag("inode"))) ks_inode_id_t;

enum ks_subsystem {
	KS_SUBSYS_OBSERVABILITY = 1,
	KS_SUBSYS_NETWORK = 2,
	KS_SUBSYS_SECURITY = 3,
	KS_SUBSYS_SCHED = 4,
	KS_SUBSYS_IO_URING = 5,
	KS_SUBSYS_MEMORY = 6,
};

enum ks_event_type {
	KS_EVT_SCHED_WAKE = 1,
	KS_EVT_SCHED_SWITCH = 2,
	KS_EVT_SCHED_HINT = 3,
	KS_EVT_MEM_FAULT = 4,
	KS_EVT_MEM_ALLOC_FAIL = 5,
	KS_EVT_OOM = 6,
	KS_EVT_XDP_DECISION = 7,
	KS_EVT_TC_QUOTA = 8,
	KS_EVT_LSM_DENY = 9,
	KS_EVT_LSM_AUDIT = 10,
	KS_EVT_IO_SUBMIT = 11,
	KS_EVT_IO_COMPLETE = 12,
	KS_EVT_USER_HEAP = 13,
	KS_EVT_MEM_PAGE_ALLOC = 14,
};

enum ks_action {
	KS_ACTION_ALLOW = 1,
	KS_ACTION_DROP = 2,
	KS_ACTION_REDIRECT = 3,
	KS_ACTION_DENY = 4,
};

enum ks_lsm_op {
	KS_LSM_FILE_OPEN = 1,
	KS_LSM_SOCKET_CONNECT = 2,
	KS_LSM_SETUID = 3,
	KS_LSM_RENAME = 4,
	KS_LSM_MKDIR = 5,
	KS_LSM_BPF_MAP_ALLOC = 6,
	KS_LSM_FILE_IOCTL = 7,
};

struct ks_event_hdr {
	__u64 ts_ns;
	__u32 pid;
	__u32 tgid;
	__u32 cpu;
	__u16 subsystem;
	__u16 event_type;
};

struct ks_sched_payload {
	__u32 subject_pid;
	__u32 peer_pid;
	__u32 run_cpu;
	__u32 latency_bucket;
	__u64 latency_ns;
	__u64 vruntime_snapshot_ns;
};

struct ks_mem_payload {
	__u64 address;
	__u64 detail;
	__u32 order;
	__u32 gfp_flags;
};

struct ks_net_payload {
	__u32 saddr4;
	__u32 daddr4;
	__u16 sport;
	__u16 dport;
	__u16 ifindex;
	__u8 proto;
	__u8 action;
	ks_cgroup_id_t cgroup_id;
	__u64 bytes;
};

struct ks_sec_payload {
	__u32 uid;
	__u32 aux;
	__u64 arg0;
	__u64 arg1;
	__u32 op;
	__s32 decision;
};

struct ks_io_payload {
	__u32 opcode;
	__u32 bucket;
	__u64 latency_ns;
	__u64 sq_depth;
};

struct ks_heap_payload {
	__u64 ptr;
	__u64 size;
	__u32 kind;
};

struct ks_event {
	struct ks_event_hdr hdr;
	union {
		struct ks_sched_payload sched;
		struct ks_mem_payload mem;
		struct ks_net_payload net;
		struct ks_sec_payload sec;
		struct ks_io_payload io;
		struct ks_heap_payload heap;
	};
};

struct ks_conntrack_key {
	__u32 saddr4;
	__u32 daddr4;
	__u16 sport;
	__u16 dport;
	__u8 proto;
	__u8 pad[3];
};

struct ks_conntrack_value {
	__u64 last_seen_ns;
	__u64 packets;
	__u64 bytes;
	__u32 redirect_slot;
	__u8 state;
	__u8 action;
	__u16 pad;
};

struct ks_l4_policy_key {
	__u8 proto;
	__u8 pad;
	__u16 dport;
};

struct ks_l4_policy_value {
	__u32 action;
	__u32 redirect_slot;
};

struct ks_cgroup_quota {
	__u64 bytes_per_window;
	__u64 window_start_ns;
	__u64 bytes_used;
	__u64 window_ns;
};

struct ks_uid_inode_key {
	__u32 uid;
	__u32 dev;
	ks_inode_id_t ino;
};

struct ks_uid_inode_rule {
	__u32 allow;
	__u32 audit;
};

struct ks_socket_rule_key {
	__u32 daddr4;
	__u16 dport;
	__u8 proto;
	__u8 family;
};

struct ks_uid_transition_key {
	__u32 old_uid;
	__u32 new_uid;
};

struct ks_cgroup_op_key {
	ks_cgroup_id_t cgroup_id;
	__u32 op;
	__u32 pad;
};

struct ks_cgroup_op_rule {
	__u32 allow;
	__u32 audit;
};

struct ks_syscall_allowlist {
	__u64 words[KS_MAX_SYSCALL_WORDS];
};

struct ks_pid_heat_slot {
	__u32 pid;
	__u32 last_cpu;
	__u32 cache_residency_score;
	__u32 last_miss_cpu;
	__u64 last_run_ns;
};

struct ks_task_stats {
	__u64 last_wakeup_ns;
	__u64 last_run_ns;
	__u64 vruntime_snapshot_ns;
	__u64 wake_latency_hist[KS_HIST_BUCKETS];
	__u64 voluntary_ctx_switches;
	__u64 involuntary_ctx_switches;
	__u64 numa_imbalance_score;
	__u32 last_cpu;
	__u32 cache_residency_score;
};

struct ks_io_hist {
	__u64 buckets[KS_HIST_BUCKETS];
};

struct ks_pressure_sample {
	__u64 page_faults;
	__u64 alloc_failures;
	__u64 oom_kills;
	__u64 hugepage_failures;
	__u64 slab_fragmentation_events;
	__u64 kswapd_wakeups;
};

struct ks_flow_scratch {
	struct ks_conntrack_key key;
	__u32 packet_len;
	__u32 ingress_ifindex;
};

struct ks_alloc_scratch {
	__u32 order;
	__u32 gfp_flags;
};

static __always_inline __u64 ks_now_ns(void)
{
	return bpf_ktime_get_ns();
}

static __always_inline __u64 ks_pid_tgid(void)
{
	return bpf_get_current_pid_tgid();
}

static __always_inline __u32 ks_pid(void)
{
	return (__u32)ks_pid_tgid();
}

static __always_inline __u32 ks_tgid(void)
{
	return (__u32)(ks_pid_tgid() >> 32);
}

static __always_inline __u32 ks_cpu(void)
{
	return (__u32)bpf_get_smp_processor_id();
}

static __always_inline __u32 ks_bucket_pow2(__u64 value)
{
	__u32 bucket;

	if (!value)
		return 0;

	bucket = 63 - __builtin_clzll(value);
	if (bucket >= KS_HIST_BUCKETS)
		bucket = KS_HIST_BUCKETS - 1;
	return bucket;
}

static __always_inline void ks_fill_hdr(struct ks_event *event, __u16 subsystem,
					 __u16 event_type)
{
	event->hdr.ts_ns = ks_now_ns();
	event->hdr.pid = ks_pid();
	event->hdr.tgid = ks_tgid();
	event->hdr.cpu = ks_cpu();
	event->hdr.subsystem = subsystem;
	event->hdr.event_type = event_type;
}

static __always_inline __u32 ks_pid_slot(__u32 pid)
{
	return pid & (KS_MAX_PID_SLOTS - 1);
}

static __always_inline __u64 ks_current_vruntime(void)
{
	struct task_struct *task;

	task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task)
		return 0;
	if (!bpf_core_field_exists(task->se.vruntime))
		return 0;
	return BPF_CORE_READ(task, se.vruntime);
}

#endif
