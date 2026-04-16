use anyhow::Result;

use crate::model::{
    IoOpcodeSnapshot, NetworkQuotaSnapshot, SchedHint, SecurityAudit, SnapshotBundle, TaskSnapshot,
    PressureSample, HIST_BUCKETS,
};
use crate::policy::CompiledPolicy;

pub trait KernelRuntime: Send + Sync + 'static {
    fn snapshot(&self) -> Result<SnapshotBundle>;
    fn apply_policy(&self, policy: &CompiledPolicy) -> Result<()>;
    fn emit_sched_hints(&self, hints: &[SchedHint]) -> Result<usize>;
}

#[derive(Debug, Default)]
pub struct StubRuntime;

impl KernelRuntime for StubRuntime {
    fn snapshot(&self) -> Result<SnapshotBundle> {
        let mut wake_hist_a = [0_u64; HIST_BUCKETS];
        let mut wake_hist_b = [0_u64; HIST_BUCKETS];
        let mut io_hist = [0_u64; HIST_BUCKETS];

        wake_hist_a[8] = 22;
        wake_hist_a[11] = 3;
        wake_hist_b[7] = 17;
        wake_hist_b[10] = 5;
        io_hist[9] = 42;
        io_hist[14] = 4;

        Ok(SnapshotBundle {
            ts_ns: monotonic_now_ns(),
            tasks: vec![
                TaskSnapshot {
                    pid: 1201,
                    vruntime_snapshot_ns: 220_000,
                    wake_latency_hist: wake_hist_a,
                    voluntary_ctx_switches: 92,
                    involuntary_ctx_switches: 8,
                    numa_imbalance_score: 2,
                    last_cpu: 3,
                },
                TaskSnapshot {
                    pid: 1217,
                    vruntime_snapshot_ns: 480_000,
                    wake_latency_hist: wake_hist_b,
                    voluntary_ctx_switches: 41,
                    involuntary_ctx_switches: 19,
                    numa_imbalance_score: 7,
                    last_cpu: 11,
                },
            ],
            network: vec![
                NetworkQuotaSnapshot {
                    cgroup_id: 4026531835,
                    bytes_used: 12_400_000,
                    bytes_budget: 25_000_000,
                    window_ns: 1_000_000_000,
                },
                NetworkQuotaSnapshot {
                    cgroup_id: 4026532198,
                    bytes_used: 6_200_000,
                    bytes_budget: 12_500_000,
                    window_ns: 1_000_000_000,
                },
            ],
            security: vec![SecurityAudit {
                ts_ns: monotonic_now_ns(),
                uid: 1000,
                op: 2,
                decision: -1,
                arg0: 0x7f000001,
                arg1: 443,
            }],
            io: vec![IoOpcodeSnapshot {
                opcode: 1,
                latency_hist: io_hist,
            }],
            pressure: PressureSample {
                ts_ns: monotonic_now_ns(),
                page_faults: 920,
                alloc_failures: 3,
                oom_kills: 0,
                hugepage_failures: 2,
                kswapd_wakeups: 18,
            },
        })
    }

    fn apply_policy(&self, _policy: &CompiledPolicy) -> Result<()> {
        Ok(())
    }

    fn emit_sched_hints(&self, hints: &[SchedHint]) -> Result<usize> {
        Ok(hints.len())
    }
}

fn monotonic_now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or_default()
}

