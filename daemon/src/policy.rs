use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyDocument {
    #[serde(default)]
    pub file_rules: Vec<FileRule>,
    #[serde(default)]
    pub cgroup_syscalls: Vec<CgroupSyscallRule>,
    #[serde(default)]
    pub socket_rules: Vec<SocketRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileRule {
    pub uid: u32,
    pub path: PathBuf,
    pub allow: bool,
    #[serde(default)]
    pub audit: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CgroupSyscallRule {
    pub cgroup_id: u64,
    pub syscalls: Vec<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SocketRule {
    pub family: u8,
    pub proto: u8,
    pub address: std::net::Ipv4Addr,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct CompiledFileRule {
    pub uid: u32,
    pub dev: u64,
    pub ino: u64,
    pub allow: bool,
    pub audit: bool,
}

#[derive(Debug, Clone)]
pub struct CompiledSocketRule {
    pub family: u8,
    pub proto: u8,
    pub address_be: u32,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub file_rules: Vec<CompiledFileRule>,
    pub cgroup_syscalls: Vec<CgroupSyscallRule>,
    pub socket_rules: Vec<CompiledSocketRule>,
}

impl PolicyDocument {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(path.as_ref())
            .with_context(|| format!("failed to read policy file {}", path.as_ref().display()))?;
        let policy = serde_json::from_str(&raw).context("failed to parse policy json")?;
        Ok(policy)
    }

    pub fn compile(&self) -> Result<CompiledPolicy> {
        let file_rules = self
            .file_rules
            .iter()
            .map(|rule| resolve_file_rule(&rule.path, rule.uid, rule.allow, rule.audit))
            .collect::<Result<Vec<_>>>()?;

        let socket_rules = self
            .socket_rules
            .iter()
            .map(|rule| CompiledSocketRule {
                family: rule.family,
                proto: rule.proto,
                address_be: u32::from(rule.address).to_be(),
                port: rule.port,
            })
            .collect();

        Ok(CompiledPolicy {
            file_rules,
            cgroup_syscalls: self.cgroup_syscalls.clone(),
            socket_rules,
        })
    }
}

fn resolve_file_rule(path: &Path, uid: u32, allow: bool, audit: bool) -> Result<CompiledFileRule> {
    let meta = fs::metadata(path)
        .with_context(|| format!("failed to stat policy path {}", path.display()))?;

    Ok(CompiledFileRule {
        uid,
        dev: meta.dev(),
        ino: meta.ino(),
        allow,
        audit,
    })
}

