use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Clone, Parser)]
pub struct Config {
    #[arg(long, default_value = "127.0.0.1:50051")]
    pub listen: SocketAddr,
    #[arg(long, default_value = "/sys/fs/bpf/kernelsentinel")]
    pub bpffs_root: PathBuf,
    #[arg(long, default_value_t = true)]
    pub stub_runtime: bool,
    #[arg(long, default_value_t = 250)]
    pub stream_interval_ms: u64,
}

