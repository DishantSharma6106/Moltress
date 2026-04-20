// SPDX-License-Identifier: GPL-2.0-only
#include "include/kernelsentinel/common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct ks_l4_policy_key);
	__type(value, struct ks_l4_policy_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} l4_policy SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, 131072);
	__type(key, struct ks_conntrack_key);
	__type(value, struct ks_conntrack_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} conntrack SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, ks_cgroup_id_t);
	__type(value, struct ks_cgroup_quota);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cgroup_net_quota SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct ks_uid_inode_key);
	__type(value, struct ks_uid_inode_rule);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} uid_inode_policy SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct ks_socket_rule_key);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} socket_allowlist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct ks_uid_transition_key);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} uid_transition_policy SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct ks_cgroup_op_key);
	__type(value, struct ks_cgroup_op_rule);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cgroup_operation_policy SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, ks_cgroup_id_t);
	__type(value, struct ks_syscall_allowlist);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cgroup_syscalls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct ks_task_stats);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} task_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, KS_MAX_PID_SLOTS);
	__type(key, __u32);
	__type(value, struct ks_pid_heat_slot);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cpu_affinity_heat SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, KS_MAX_OPCODE);
	__type(key, __u32);
	__type(value, struct ks_io_hist);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} io_opcode_hist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ks_pressure_sample);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} memory_pressure SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ks_flow_scratch);
} xdp_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ks_alloc_scratch);
} alloc_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, KS_RINGBUF_SIZE);
} observability_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, KS_RINGBUF_SIZE);
} network_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, KS_RINGBUF_SIZE);
} security_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, KS_RINGBUF_SIZE);
} io_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dispatch_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_devmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, struct bpf_cpumap_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_cpumap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sock_redirect SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 8192);
	__type(key, struct ks_socket_rule_key);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sock_ops_index SEC(".maps");

static __always_inline void ks_emit_sched_event(__u16 event_type, __u32 subject_pid,
						__u32 peer_pid, __u64 latency_ns,
						__u64 vruntime_snapshot_ns)
{
	struct ks_event *event;

	event = bpf_ringbuf_reserve(&observability_events, sizeof(*event), 0);
	if (!event)
		return;

	ks_fill_hdr(event, KS_SUBSYS_SCHED, event_type);
	event->sched.subject_pid = subject_pid;
	event->sched.peer_pid = peer_pid;
	event->sched.run_cpu = ks_cpu();
	event->sched.latency_ns = latency_ns;
	event->sched.latency_bucket = ks_bucket_pow2(latency_ns);
	event->sched.vruntime_snapshot_ns = vruntime_snapshot_ns;
	bpf_ringbuf_submit(event, 0);
}

static __always_inline void ks_emit_mem_event(__u16 event_type, __u64 address, __u64 detail,
					      __u32 order, __u32 gfp_flags)
{
	struct ks_event *event;

	event = bpf_ringbuf_reserve(&observability_events, sizeof(*event), 0);
	if (!event)
		return;

	ks_fill_hdr(event, KS_SUBSYS_MEMORY, event_type);
	event->mem.address = address;
	event->mem.detail = detail;
	event->mem.order = order;
	event->mem.gfp_flags = gfp_flags;
	bpf_ringbuf_submit(event, 0);
}

static __always_inline void ks_emit_net_event(__u16 event_type, struct ks_conntrack_key *key,
					      __u8 action, __u16 ifindex,
					      ks_cgroup_id_t cgroup_id, __u64 bytes)
{
	struct ks_event *event;

	event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
	if (!event)
		return;

	ks_fill_hdr(event, KS_SUBSYS_NETWORK, event_type);
	event->net.saddr4 = key->saddr4;
	event->net.daddr4 = key->daddr4;
	event->net.sport = key->sport;
	event->net.dport = key->dport;
	event->net.proto = key->proto;
	event->net.action = action;
	event->net.ifindex = ifindex;
	event->net.cgroup_id = cgroup_id;
	event->net.bytes = bytes;
	bpf_ringbuf_submit(event, 0);
}

static __always_inline void ks_emit_sec_event(__u16 event_type, __u32 uid, __u32 op,
					      __u64 arg0, __u64 arg1, __s32 decision)
{
	struct ks_event *event;

	event = bpf_ringbuf_reserve(&security_events, sizeof(*event), 0);
	if (!event)
		return;

	ks_fill_hdr(event, KS_SUBSYS_SECURITY, event_type);
	event->sec.uid = uid;
	event->sec.op = op;
	event->sec.arg0 = arg0;
	event->sec.arg1 = arg1;
	event->sec.decision = decision;
	bpf_ringbuf_submit(event, 0);
}

static __always_inline void ks_emit_io_event(__u16 event_type, __u32 opcode,
					     __u64 latency_ns, __u64 sq_depth)
{
	struct ks_event *event;

	event = bpf_ringbuf_reserve(&io_events, sizeof(*event), 0);
	if (!event)
		return;

	ks_fill_hdr(event, KS_SUBSYS_IO_URING, event_type);
	event->io.opcode = opcode;
	event->io.latency_ns = latency_ns;
	event->io.bucket = ks_bucket_pow2(latency_ns);
	event->io.sq_depth = sq_depth;
	bpf_ringbuf_submit(event, 0);
}

static __always_inline struct ks_task_stats *ks_lookup_task_stats(__u32 pid)
{
	struct ks_task_stats *stats;
	struct ks_task_stats zero = {};

	stats = bpf_map_lookup_elem(&task_stats, &pid);
	if (stats)
		return stats;

	bpf_map_update_elem(&task_stats, &pid, &zero, BPF_ANY);
	return bpf_map_lookup_elem(&task_stats, &pid);
}

static __always_inline void ks_mark_run(__u32 pid, __u64 now)
{
	struct ks_task_stats *stats;
	struct ks_pid_heat_slot *slot;
	__u32 slot_idx;

	stats = ks_lookup_task_stats(pid);
	if (!stats)
		return;

	stats->last_run_ns = now;
	stats->last_cpu = ks_cpu();
	stats->vruntime_snapshot_ns = ks_current_vruntime();

	slot_idx = ks_pid_slot(pid);
	slot = bpf_map_lookup_elem(&cpu_affinity_heat, &slot_idx);
	if (!slot)
		return;

	slot->pid = pid;
	slot->last_cpu = ks_cpu();
	slot->last_run_ns = now;
	slot->cache_residency_score = 100;
}

static __always_inline int ks_account_quota(ks_cgroup_id_t cgroup_id, __u64 packet_len)
{
	struct ks_cgroup_quota *quota;
	__u64 now = ks_now_ns();

	quota = bpf_map_lookup_elem(&cgroup_net_quota, &cgroup_id);
	if (!quota)
		return 0;

	if (quota->window_ns && now - quota->window_start_ns > quota->window_ns) {
		quota->window_start_ns = now;
		quota->bytes_used = 0;
	}

	quota->bytes_used += packet_len;
	if (quota->bytes_used > quota->bytes_per_window)
		return -1;

	return 0;
}

static __always_inline void ks_pressure_inc(__u64 *field)
{
	if (field)
		(*field)++;
}

static __always_inline struct ethhdr *ks_parse_eth(void *data, void *data_end, __u16 *h_proto)
{
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return NULL;

	*h_proto = bpf_ntohs(eth->h_proto);
	return eth;
}

static __always_inline int ks_parse_ipv4_tuple(void *data, void *data_end,
					       struct ks_conntrack_key *key)
{
	struct iphdr *iph;
	__u64 offset = sizeof(struct ethhdr);

	iph = data + offset;
	if ((void *)(iph + 1) > data_end)
		return -1;

	if (iph->ihl < 5)
		return -1;
	if ((void *)iph + iph->ihl * 4 > data_end)
		return -1;

	key->saddr4 = iph->saddr;
	key->daddr4 = iph->daddr;
	key->proto = iph->protocol;

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = (void *)iph + iph->ihl * 4;

		if ((void *)(tcp + 1) > data_end)
			return -1;
		key->sport = tcp->source;
		key->dport = tcp->dest;
		return 0;
	}

	if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udp = (void *)iph + iph->ihl * 4;

		if ((void *)(udp + 1) > data_end)
			return -1;
		key->sport = udp->source;
		key->dport = udp->dest;
		return 0;
	}

	return -1;
}

static __always_inline int ks_xdp_eval_policy(struct xdp_md *ctx, struct ks_conntrack_key *key,
					      __u32 packet_len)
{
	struct ks_conntrack_value *state;
	struct ks_l4_policy_value *policy;
	struct ks_l4_policy_key policy_key = {
		.proto = key->proto,
		.dport = bpf_ntohs(key->dport),
	};
	struct ks_conntrack_value new_state = {
		.last_seen_ns = ks_now_ns(),
		.packets = 1,
		.bytes = packet_len,
		.action = KS_ACTION_DROP,
	};

	state = bpf_map_lookup_elem(&conntrack, key);
	if (state) {
		state->last_seen_ns = ks_now_ns();
		state->packets++;
		state->bytes += packet_len;
		if (state->action == KS_ACTION_REDIRECT)
			return bpf_redirect_map(&xdp_devmap, state->redirect_slot, 0);
		return state->action == KS_ACTION_DROP ? XDP_DROP : XDP_PASS;
	}

	policy = bpf_map_lookup_elem(&l4_policy, &policy_key);
	if (!policy)
		return XDP_DROP;

	new_state.action = policy->action;
	new_state.redirect_slot = policy->redirect_slot;
	bpf_map_update_elem(&conntrack, key, &new_state, BPF_ANY);

	if (policy->action == KS_ACTION_REDIRECT)
		return bpf_redirect_map(&xdp_devmap, policy->redirect_slot, 0);
	if (policy->action == KS_ACTION_DROP)
		return XDP_DROP;
	return XDP_PASS;
}

SEC("fentry/pick_next_task_fair")
int BPF_PROG(ks_fentry_pick_next_task_fair)
{
	ks_emit_sched_event(KS_EVT_SCHED_HINT, ks_pid(), 0, 0, 0);
	return 0;
}

SEC("fentry/__schedule")
int BPF_PROG(ks_fentry___schedule)
{
	ks_mark_run(ks_pid(), ks_now_ns());
	return 0;
}

SEC("fentry/try_to_wake_up")
int BPF_PROG(ks_fentry_try_to_wake_up)
{
	struct ks_task_stats *stats;
	__u32 pid = ks_pid();

	stats = ks_lookup_task_stats(pid);
	if (!stats)
		return 0;

	stats->last_wakeup_ns = ks_now_ns();
	ks_emit_sched_event(KS_EVT_SCHED_WAKE, pid, 0, 0, stats->vruntime_snapshot_ns);
	return 0;
}

SEC("kprobe/do_page_fault")
int BPF_KPROBE(ks_kprobe_do_page_fault)
{
	__u32 key = 0;
	struct ks_pressure_sample *pressure = bpf_map_lookup_elem(&memory_pressure, &key);

	if (pressure)
		ks_pressure_inc(&pressure->page_faults);
	ks_emit_mem_event(KS_EVT_MEM_FAULT, 0, 0, 0, 0);
	return 0;
}

SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(ks_kprobe_handle_mm_fault)
{
	__u32 key = 0;
	struct ks_pressure_sample *pressure = bpf_map_lookup_elem(&memory_pressure, &key);

	if (pressure)
		ks_pressure_inc(&pressure->page_faults);
	return 0;
}

SEC("kprobe/__alloc_pages_nodemask")
int BPF_KPROBE(ks_kprobe___alloc_pages_nodemask, gfp_t gfp_mask, unsigned int order)
{
	__u32 key = 0;
	struct ks_alloc_scratch *scratch = bpf_map_lookup_elem(&alloc_scratch, &key);

	if (!scratch)
		return 0;

	scratch->order = order;
	scratch->gfp_flags = gfp_mask;
	return 0;
}

SEC("kprobe/wakeup_kswapd")
int BPF_KPROBE(ks_kprobe_wakeup_kswapd)
{
	__u32 key = 0;
	struct ks_pressure_sample *pressure = bpf_map_lookup_elem(&memory_pressure, &key);

	if (pressure)
		ks_pressure_inc(&pressure->kswapd_wakeups);
	return 0;
}

SEC("kretprobe/__alloc_pages_nodemask")
int BPF_KRETPROBE(ks_kretprobe___alloc_pages_nodemask, struct page *page)
{
	__u32 key = 0;
	struct ks_pressure_sample *pressure = bpf_map_lookup_elem(&memory_pressure, &key);
	struct ks_alloc_scratch *scratch = bpf_map_lookup_elem(&alloc_scratch, &key);
	__u32 order = scratch ? scratch->order : 0;
	__u32 gfp_flags = scratch ? scratch->gfp_flags : 0;

	if (page)
		return 0;

	if (pressure)
		ks_pressure_inc(&pressure->alloc_failures);
	if (pressure && order >= 9)
		ks_pressure_inc(&pressure->hugepage_failures);
	ks_emit_mem_event(KS_EVT_MEM_ALLOC_FAIL, 0, 0, order, gfp_flags);
	return 0;
}

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(ks_kprobe_oom_kill_process)
{
	__u32 key = 0;
	struct ks_pressure_sample *pressure = bpf_map_lookup_elem(&memory_pressure, &key);

	if (pressure)
		ks_pressure_inc(&pressure->oom_kills);
	ks_emit_mem_event(KS_EVT_OOM, 0, 0, 0, 0);
	return 0;
}

SEC("tracepoint/sched/sched_wakeup_new")
int ks_tp_sched_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
	struct ks_task_stats *stats;
	__u32 pid = ctx->pid;

	stats = ks_lookup_task_stats(pid);
	if (!stats)
		return 0;

	stats->last_wakeup_ns = ks_now_ns();
	ks_emit_sched_event(KS_EVT_SCHED_WAKE, pid, 0, 0, stats->vruntime_snapshot_ns);
	return 0;
}

SEC("tracepoint/sched/sched_switch")
int ks_tp_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	struct ks_task_stats *prev_stats;
	struct ks_task_stats *next_stats;
	__u64 now = ks_now_ns();
	__u64 delta = 0;
	__u32 bucket = 0;

	prev_stats = ks_lookup_task_stats(ctx->prev_pid);
	next_stats = ks_lookup_task_stats(ctx->next_pid);
	if (prev_stats) {
		if (ctx->prev_state)
			prev_stats->voluntary_ctx_switches++;
		else
			prev_stats->involuntary_ctx_switches++;
	}

	if (next_stats && next_stats->last_wakeup_ns && now > next_stats->last_wakeup_ns) {
		delta = now - next_stats->last_wakeup_ns;
		bucket = ks_bucket_pow2(delta);
		next_stats->wake_latency_hist[bucket]++;
	}

	ks_mark_run(ctx->next_pid, now);
	ks_emit_sched_event(KS_EVT_SCHED_SWITCH, ctx->next_pid, ctx->prev_pid, delta,
			    next_stats ? next_stats->vruntime_snapshot_ns : 0);
	return 0;
}

SEC("tracepoint/kmem/mm_page_alloc")
int ks_tp_mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
	ks_emit_mem_event(KS_EVT_MEM_PAGE_ALLOC, 0, 0, ctx->order, ctx->gfp_flags);
	return 0;
}

SEC("raw_tp/sched_switch")
int ks_rawtp_sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
	ks_emit_sched_event(KS_EVT_SCHED_SWITCH, ks_pid(), 0, 0, 0);
	return 0;
}

SEC("uprobe/libc_malloc")
int BPF_KPROBE(ks_uprobe_malloc, size_t size)
{
	struct ks_event *event;

	event = bpf_ringbuf_reserve(&observability_events, sizeof(*event), 0);
	if (!event)
		return 0;

	ks_fill_hdr(event, KS_SUBSYS_OBSERVABILITY, KS_EVT_USER_HEAP);
	event->heap.ptr = 0;
	event->heap.size = size;
	event->heap.kind = 1;
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("uprobe/libc_free")
int BPF_KPROBE(ks_uprobe_free, void *ptr)
{
	struct ks_event *event;

	event = bpf_ringbuf_reserve(&observability_events, sizeof(*event), 0);
	if (!event)
		return 0;

	ks_fill_hdr(event, KS_SUBSYS_OBSERVABILITY, KS_EVT_USER_HEAP);
	event->heap.ptr = (__u64)ptr;
	event->heap.size = 0;
	event->heap.kind = 2;
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("xdp")
int ks_xdp_firewall(struct xdp_md *ctx)
{
	struct ks_flow_scratch *scratch;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ks_conntrack_key key = {};
	__u16 h_proto = 0;
	__u32 zero = 0;

	if (!ks_parse_eth(data, data_end, &h_proto))
		return XDP_ABORTED;
	if (h_proto != ETH_P_IP)
		return XDP_PASS;
	if (ks_parse_ipv4_tuple(data, data_end, &key) < 0)
		return XDP_PASS;

	scratch = bpf_map_lookup_elem(&xdp_scratch, &zero);
	if (scratch) {
		scratch->key = key;
		scratch->packet_len = data_end - data;
		scratch->ingress_ifindex = ctx->ingress_ifindex;
	}

	bpf_tail_call(ctx, &dispatch_table, KS_TAIL_XDP_L4);
	return ks_xdp_eval_policy(ctx, &key, data_end - data);
}

SEC("xdp")
int ks_xdp_dispatch_l4(struct xdp_md *ctx)
{
	struct ks_flow_scratch *scratch;
	int verdict;
	__u32 zero = 0;

	scratch = bpf_map_lookup_elem(&xdp_scratch, &zero);
	if (!scratch)
		return XDP_PASS;

	verdict = ks_xdp_eval_policy(ctx, &scratch->key, scratch->packet_len);
	ks_emit_net_event(
		KS_EVT_XDP_DECISION, &scratch->key,
		verdict == XDP_DROP ? KS_ACTION_DROP :
		(verdict == XDP_REDIRECT ? KS_ACTION_REDIRECT : KS_ACTION_ALLOW),
		scratch->ingress_ifindex, 0, scratch->packet_len);
	return verdict;
}

SEC("tc")
int ks_tc_ingress(struct __sk_buff *skb)
{
	ks_cgroup_id_t cgroup_id = bpf_skb_cgroup_id(skb);
	struct ks_conntrack_key key = {};

	if (ks_account_quota(cgroup_id, skb->len) < 0) {
		ks_emit_net_event(KS_EVT_TC_QUOTA, &key, KS_ACTION_DROP, skb->ifindex,
				  cgroup_id, skb->len);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

SEC("tc")
int ks_tc_egress(struct __sk_buff *skb)
{
	ks_cgroup_id_t cgroup_id = bpf_skb_cgroup_id(skb);
	struct ks_conntrack_key key = {};

	if (ks_account_quota(cgroup_id, skb->len) < 0) {
		ks_emit_net_event(KS_EVT_TC_QUOTA, &key, KS_ACTION_DROP, skb->ifindex,
				  cgroup_id, skb->len);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

SEC("sockops")
int ks_sockops(struct bpf_sock_ops *skops)
{
	struct ks_socket_rule_key key = {
		.daddr4 = skops->remote_ip4,
		.dport = bpf_ntohl(skops->remote_port),
		.proto = IPPROTO_TCP, /* bpf_sock_ops has no .protocol; sockops fires for TCP */
		.family = skops->family,
	};
	__u32 allow = 1;

	if (skops->family != AF_INET)
		return 0;

	if (!bpf_map_lookup_elem(&socket_allowlist, &key))
		return 0;

	bpf_sock_hash_update(skops, &sock_ops_index, &key, BPF_ANY);
	return allow;
}

SEC("sk_msg")
int ks_sk_msg(struct sk_msg_md *msg)
{
	return SK_PASS;
}

SEC("cgroup_skb/ingress")
int ks_cgroup_skb_ingress(struct __sk_buff *skb)
{
	if (ks_account_quota(bpf_get_current_cgroup_id(), skb->len) < 0)
		return 0;
	return 1;
}

SEC("cgroup_skb/egress")
int ks_cgroup_skb_egress(struct __sk_buff *skb)
{
	if (ks_account_quota(bpf_get_current_cgroup_id(), skb->len) < 0)
		return 0;
	return 1;
}

SEC("lsm/file_open")
int BPF_PROG(ks_lsm_file_open, struct file *file)
{
	const struct inode *inode;
	struct ks_uid_inode_key key = {};
	struct ks_uid_inode_rule *rule;
	__u64 uid_gid = bpf_get_current_uid_gid();

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;

	key.uid = (__u32)uid_gid;
	key.dev = BPF_CORE_READ(inode, i_sb, s_dev);
	key.ino = BPF_CORE_READ(inode, i_ino);

	rule = bpf_map_lookup_elem(&uid_inode_policy, &key);
	if (!rule)
		return 0;

	if (rule->audit)
		ks_emit_sec_event(KS_EVT_LSM_AUDIT, key.uid, KS_LSM_FILE_OPEN,
				  key.dev, key.ino, 0);
	if (!rule->allow) {
		ks_emit_sec_event(KS_EVT_LSM_DENY, key.uid, KS_LSM_FILE_OPEN,
				  key.dev, key.ino, -EACCES);
		return -EACCES;
	}

	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(ks_lsm_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)address;
	struct ks_socket_rule_key key = {};
	__u64 uid_gid = bpf_get_current_uid_gid();

	if (!address || addrlen < sizeof(*addr))
		return 0;
	if (BPF_CORE_READ(addr, sin_family) != AF_INET)
		return 0;

	key.family = AF_INET;
	key.proto = IPPROTO_TCP;
	key.daddr4 = BPF_CORE_READ(addr, sin_addr.s_addr);
	key.dport = bpf_ntohs(BPF_CORE_READ(addr, sin_port));

	if (bpf_map_lookup_elem(&socket_allowlist, &key))
		return 0;

	ks_emit_sec_event(KS_EVT_LSM_DENY, (__u32)uid_gid, KS_LSM_SOCKET_CONNECT,
			  key.daddr4, key.dport, -EPERM);
	return -EPERM;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(ks_lsm_task_fix_setuid, struct cred *new, const struct cred *old, int flags)
{
	struct ks_uid_transition_key key = {
		.old_uid = BPF_CORE_READ(old, uid.val),
		.new_uid = BPF_CORE_READ(new, uid.val),
	};

	if (bpf_map_lookup_elem(&uid_transition_policy, &key))
		return 0;

	ks_emit_sec_event(KS_EVT_LSM_DENY, key.old_uid, KS_LSM_SETUID,
			  key.old_uid, key.new_uid, -EPERM);
	return -EPERM;
}

SEC("lsm/inode_rename")
int BPF_PROG(ks_lsm_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	struct ks_cgroup_op_key key = {
		.cgroup_id = bpf_get_current_cgroup_id(),
		.op = KS_LSM_RENAME,
	};
	struct ks_cgroup_op_rule *rule;

	rule = bpf_map_lookup_elem(&cgroup_operation_policy, &key);
	if (!rule)
		return 0;
	if (rule->audit)
		ks_emit_sec_event(KS_EVT_LSM_AUDIT, (__u32)bpf_get_current_uid_gid(),
				  KS_LSM_RENAME, 0, 0, 0);
	if (!rule->allow) {
		ks_emit_sec_event(KS_EVT_LSM_DENY, (__u32)bpf_get_current_uid_gid(),
				  KS_LSM_RENAME, 0, 0, -EPERM);
		return -EPERM;
	}
	return 0;
}

SEC("lsm/path_mkdir")
int BPF_PROG(ks_lsm_path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode)
{
	struct ks_cgroup_op_key key = {
		.cgroup_id = bpf_get_current_cgroup_id(),
		.op = KS_LSM_MKDIR,
	};
	struct ks_cgroup_op_rule *rule;

	rule = bpf_map_lookup_elem(&cgroup_operation_policy, &key);
	if (!rule)
		return 0;
	if (rule->audit)
		ks_emit_sec_event(KS_EVT_LSM_AUDIT, (__u32)bpf_get_current_uid_gid(),
				  KS_LSM_MKDIR, mode, 0, 0);
	if (!rule->allow) {
		ks_emit_sec_event(KS_EVT_LSM_DENY, (__u32)bpf_get_current_uid_gid(),
				  KS_LSM_MKDIR, mode, 0, -EPERM);
		return -EPERM;
	}
	return 0;
}

SEC("lsm/bpf_map_alloc")
int BPF_PROG(ks_lsm_bpf_map_alloc, struct bpf_map *map)
{
	ks_emit_sec_event(KS_EVT_LSM_AUDIT, (__u32)bpf_get_current_uid_gid(),
			  KS_LSM_BPF_MAP_ALLOC, 0, 0, 0);
	return 0;
}

SEC("kprobe/security_file_ioctl")
int BPF_KPROBE(ks_kprobe_security_file_ioctl)
{
	ks_emit_sec_event(KS_EVT_LSM_AUDIT, (__u32)bpf_get_current_uid_gid(),
			  KS_LSM_FILE_IOCTL, 0, 0, 0);
	return 0;
}

SEC("fentry/io_submit_sqes")
int BPF_PROG(ks_fentry_io_submit_sqes)
{
	ks_emit_io_event(KS_EVT_IO_SUBMIT, 0, 0, 0);
	return 0;
}

SEC("fentry/io_issue_sqe")
int BPF_PROG(ks_fentry_io_issue_sqe)
{
	ks_emit_io_event(KS_EVT_IO_SUBMIT, 0, 0, 0);
	return 0;
}

SEC("fentry/io_complete_rw")
int BPF_PROG(ks_fentry_io_complete_rw)
{
	__u32 opcode = 0;
	struct ks_io_hist *hist = bpf_map_lookup_elem(&io_opcode_hist, &opcode);

	if (hist)
		hist->buckets[0]++;
	ks_emit_io_event(KS_EVT_IO_COMPLETE, opcode, 0, 0);
	return 0;
}

SEC("perf_event")
int ks_perf_llc_miss(struct bpf_perf_event_data *ctx)
{
	struct ks_task_stats *stats;
	__u32 pid = ks_pid();
	__u32 slot_idx;
	struct ks_pid_heat_slot *slot;

	stats = ks_lookup_task_stats(pid);
	if (!stats)
		return 0;

	stats->numa_imbalance_score++;
	slot_idx = ks_pid_slot(pid);
	slot = bpf_map_lookup_elem(&cpu_affinity_heat, &slot_idx);
	if (slot) {
		slot->last_miss_cpu = ks_cpu();
		if (slot->cache_residency_score)
			slot->cache_residency_score--;
	}

	return 0;
}
