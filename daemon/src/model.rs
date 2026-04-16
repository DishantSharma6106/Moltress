use serde::{Deserialize, Serialize};

pub const HIST_BUCKETS: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSnapshot {
    pub pid: u32,
    pub vruntime_snapshot_ns: u64,
    pub wake_latency_hist: [u64; HIST_BUCKETS],
    pub voluntary_ctx_switches: u64,
    pub involuntary_ctx_switches: u64,
    pub numa_imbalance_score: u64,
    pub last_cpu: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkQuotaSnapshot {
    pub cgroup_id: u64,
    pub bytes_used: u64,
    pub bytes_budget: u64,
    pub window_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAudit {
    pub ts_ns: u64,
    pub uid: u32,
    pub op: u32,
    pub decision: i32,
    pub arg0: u64,
    pub arg1: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoOpcodeSnapshot {
    pub opcode: u32,
    pub latency_hist: [u64; HIST_BUCKETS],
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PressureSample {
    pub ts_ns: u64,
    pub page_faults: u64,
    pub alloc_failures: u64,
    pub oom_kills: u64,
    pub hugepage_failures: u64,
    pub kswapd_wakeups: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotBundle {
    pub ts_ns: u64,
    pub tasks: Vec<TaskSnapshot>,
    pub network: Vec<NetworkQuotaSnapshot>,
    pub security: Vec<SecurityAudit>,
    pub io: Vec<IoOpcodeSnapshot>,
    pub pressure: PressureSample,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quantiles {
    pub p50_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMetric {
    pub pid: u32,
    pub vruntime_drift_ns: u64,
    pub wake_latency: Quantiles,
    pub voluntary_switch_ratio: f64,
    pub numa_imbalance_score: u64,
    pub last_cpu: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoLatencyMetric {
    pub opcode: u32,
    pub latency: Quantiles,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PressureSignal {
    pub ts_ns: u64,
    pub signal: f64,
    pub page_faults: u64,
    pub alloc_failures: u64,
    pub oom_kills: u64,
    pub hugepage_failures: u64,
    pub kswapd_wakeups: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardFrame {
    pub ts_ns: u64,
    pub processes: Vec<ProcessMetric>,
    pub network: Vec<NetworkQuotaSnapshot>,
    pub recent_security: Vec<SecurityAudit>,
    pub io: Vec<IoLatencyMetric>,
    pub pressure: PressureSignal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedHint {
    pub pid: u32,
    pub target_cpu: u32,
    pub latency_class: u8,
    pub weight: u32,
}

