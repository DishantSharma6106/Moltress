use crate::model::{
    DashboardFrame, IoLatencyMetric, IoOpcodeSnapshot, PressureSample, PressureSignal, ProcessMetric,
    Quantiles, SnapshotBundle, TaskSnapshot, HIST_BUCKETS,
};

fn bucket_upper_bound(bucket: usize) -> u64 {
    1_u64 << bucket.min(HIST_BUCKETS - 1)
}

fn quantile_from_hist(hist: &[u64; HIST_BUCKETS], q: f64) -> u64 {
    let total: u64 = hist.iter().sum();
    if total == 0 {
        return 0;
    }

    let threshold = ((total as f64) * q).ceil() as u64;
    let mut seen = 0_u64;

    for (bucket, count) in hist.iter().enumerate() {
        seen += *count;
        if seen >= threshold {
            return bucket_upper_bound(bucket);
        }
    }

    bucket_upper_bound(HIST_BUCKETS - 1)
}

fn task_metric(task: &TaskSnapshot) -> ProcessMetric {
    let total_switches = task.voluntary_ctx_switches + task.involuntary_ctx_switches;
    let voluntary_switch_ratio = if total_switches == 0 {
        0.0
    } else {
        task.voluntary_ctx_switches as f64 / total_switches as f64
    };

    ProcessMetric {
        pid: task.pid,
        vruntime_drift_ns: task.vruntime_snapshot_ns,
        wake_latency: Quantiles {
            p50_ns: quantile_from_hist(&task.wake_latency_hist, 0.50),
            p99_ns: quantile_from_hist(&task.wake_latency_hist, 0.99),
            p999_ns: quantile_from_hist(&task.wake_latency_hist, 0.999),
        },
        voluntary_switch_ratio,
        numa_imbalance_score: task.numa_imbalance_score,
        last_cpu: task.last_cpu,
    }
}

fn io_metric(sample: &IoOpcodeSnapshot) -> IoLatencyMetric {
    IoLatencyMetric {
        opcode: sample.opcode,
        latency: Quantiles {
            p50_ns: quantile_from_hist(&sample.latency_hist, 0.50),
            p99_ns: quantile_from_hist(&sample.latency_hist, 0.99),
            p999_ns: quantile_from_hist(&sample.latency_hist, 0.999),
        },
    }
}

pub fn pressure_signal(sample: &PressureSample) -> PressureSignal {
    let signal = (sample.page_faults as f64 * 0.1)
        + (sample.alloc_failures as f64 * 3.0)
        + (sample.oom_kills as f64 * 20.0)
        + (sample.hugepage_failures as f64 * 2.0)
        + (sample.kswapd_wakeups as f64 * 0.5);

    PressureSignal {
        ts_ns: sample.ts_ns,
        signal,
        page_faults: sample.page_faults,
        alloc_failures: sample.alloc_failures,
        oom_kills: sample.oom_kills,
        hugepage_failures: sample.hugepage_failures,
        kswapd_wakeups: sample.kswapd_wakeups,
    }
}

pub fn build_dashboard(bundle: SnapshotBundle) -> DashboardFrame {
    let processes = bundle.tasks.iter().map(task_metric).collect();
    let io = bundle.io.iter().map(io_metric).collect();
    let pressure = pressure_signal(&bundle.pressure);

    DashboardFrame {
        ts_ns: bundle.ts_ns,
        processes,
        network: bundle.network,
        recent_security: bundle.security,
        io,
        pressure,
    }
}

