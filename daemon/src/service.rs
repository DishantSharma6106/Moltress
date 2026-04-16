use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::analytics::{build_dashboard, pressure_signal};
use crate::model::{DashboardFrame as ModelDashboardFrame, PressureSignal as ModelPressureSignal};
use crate::runtime::KernelRuntime;

pub mod pb {
    tonic::include_proto!("kernelsentinel.v1");
}

use pb::kernel_sentinel_server::{KernelSentinel, KernelSentinelServer};
use pb::{
    DashboardFrame, IoLatencyMetric, NetworkMetric, PressureFrame, ProcessMetric, Quantiles,
    SecurityAuditFrame, SecurityEvent, WatchRequest,
};

type DashboardStream = Pin<Box<dyn Stream<Item = Result<DashboardFrame, Status>> + Send>>;
type PressureStream = Pin<Box<dyn Stream<Item = Result<PressureFrame, Status>> + Send>>;
type AuditStream = Pin<Box<dyn Stream<Item = Result<SecurityAuditFrame, Status>> + Send>>;

pub fn server<R>(runtime: Arc<R>, default_interval_ms: u64) -> KernelSentinelServer<Service<R>>
where
    R: KernelRuntime,
{
    KernelSentinelServer::new(Service {
        runtime,
        default_interval_ms,
    })
}

#[derive(Clone)]
pub struct Service<R> {
    runtime: Arc<R>,
    default_interval_ms: u64,
}

#[tonic::async_trait]
impl<R> KernelSentinel for Service<R>
where
    R: KernelRuntime,
{
    type WatchDashboardStream = DashboardStream;
    type WatchPressureStream = PressureStream;
    type WatchAuditStream = AuditStream;

    async fn watch_dashboard(
        &self,
        request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchDashboardStream>, Status> {
        let interval_ms = interval_or_default(request.get_ref().interval_ms, self.default_interval_ms);
        let runtime = Arc::clone(&self.runtime);
        let (tx, rx) = mpsc::channel(8);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
            loop {
                ticker.tick().await;
                let bundle = match runtime.snapshot() {
                    Ok(bundle) => bundle,
                    Err(err) => {
                        let _ = tx.send(Err(Status::internal(err.to_string()))).await;
                        break;
                    }
                };

                let frame = dashboard_to_proto(build_dashboard(bundle));
                if tx.send(Ok(frame)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn watch_pressure(
        &self,
        request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchPressureStream>, Status> {
        let interval_ms = interval_or_default(request.get_ref().interval_ms, self.default_interval_ms);
        let runtime = Arc::clone(&self.runtime);
        let (tx, rx) = mpsc::channel(8);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
            loop {
                ticker.tick().await;
                let bundle = match runtime.snapshot() {
                    Ok(bundle) => bundle,
                    Err(err) => {
                        let _ = tx.send(Err(Status::internal(err.to_string()))).await;
                        break;
                    }
                };

                let frame = pressure_to_proto(pressure_signal(&bundle.pressure));
                if tx.send(Ok(frame)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn watch_audit(
        &self,
        request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchAuditStream>, Status> {
        let interval_ms = interval_or_default(request.get_ref().interval_ms, self.default_interval_ms);
        let runtime = Arc::clone(&self.runtime);
        let (tx, rx) = mpsc::channel(8);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
            loop {
                ticker.tick().await;
                let bundle = match runtime.snapshot() {
                    Ok(bundle) => bundle,
                    Err(err) => {
                        let _ = tx.send(Err(Status::internal(err.to_string()))).await;
                        break;
                    }
                };

                let events = bundle.security.into_iter().map(audit_to_proto).collect();
                if tx.send(Ok(SecurityAuditFrame { events })).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

fn interval_or_default(requested: u64, default_ms: u64) -> u64 {
    if requested == 0 {
        default_ms
    } else {
        requested
    }
}

fn dashboard_to_proto(frame: ModelDashboardFrame) -> DashboardFrame {
    DashboardFrame {
        ts_ns: frame.ts_ns,
        processes: frame.processes.into_iter().map(process_to_proto).collect(),
        network: frame.network.into_iter().map(network_to_proto).collect(),
        recent_security: frame.recent_security.into_iter().map(audit_to_proto).collect(),
        io: frame.io.into_iter().map(io_to_proto).collect(),
        pressure: Some(pressure_to_proto(frame.pressure)),
    }
}

fn process_to_proto(metric: crate::model::ProcessMetric) -> ProcessMetric {
    ProcessMetric {
        pid: metric.pid,
        vruntime_drift_ns: metric.vruntime_drift_ns,
        wake_latency: Some(quantiles_to_proto(metric.wake_latency)),
        voluntary_switch_ratio: metric.voluntary_switch_ratio,
        numa_imbalance_score: metric.numa_imbalance_score,
        last_cpu: metric.last_cpu,
    }
}

fn network_to_proto(metric: crate::model::NetworkQuotaSnapshot) -> NetworkMetric {
    NetworkMetric {
        cgroup_id: metric.cgroup_id,
        bytes_used: metric.bytes_used,
        bytes_budget: metric.bytes_budget,
        window_ns: metric.window_ns,
    }
}

fn audit_to_proto(event: crate::model::SecurityAudit) -> SecurityEvent {
    SecurityEvent {
        ts_ns: event.ts_ns,
        uid: event.uid,
        op: event.op,
        decision: event.decision,
        arg0: event.arg0,
        arg1: event.arg1,
    }
}

fn io_to_proto(metric: crate::model::IoLatencyMetric) -> IoLatencyMetric {
    IoLatencyMetric {
        opcode: metric.opcode,
        latency: Some(quantiles_to_proto(metric.latency)),
    }
}

fn pressure_to_proto(signal: ModelPressureSignal) -> PressureFrame {
    PressureFrame {
        ts_ns: signal.ts_ns,
        signal: signal.signal,
        page_faults: signal.page_faults,
        alloc_failures: signal.alloc_failures,
        oom_kills: signal.oom_kills,
        hugepage_failures: signal.hugepage_failures,
        kswapd_wakeups: signal.kswapd_wakeups,
    }
}

fn quantiles_to_proto(q: crate::model::Quantiles) -> Quantiles {
    Quantiles {
        p50_ns: q.p50_ns,
        p99_ns: q.p99_ns,
        p999_ns: q.p999_ns,
    }
}

