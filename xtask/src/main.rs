use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    Gen,
    Build,
    Test,
    Vmtest,
    Lint,
    Proto,
    SyncHome {
        #[arg(long)]
        dest: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let repo = repo_root()?;

    match cli.command {
        Cmd::Gen => {
            run_script(&repo, "scripts/extract-btf.sh")?;
            build_bpf(&repo)?;
            gen_skeletons(&repo)?;
            run_script(&repo, "scripts/gen-proto.sh")?;
        }
        Cmd::Build => {
            build_bpf(&repo)?;
            cargo_in(&repo, &["build", "--workspace"])?;
        }
        Cmd::Test => cargo_in(&repo, &["test", "--workspace"])?,
        Cmd::Vmtest => run_script(&repo, "scripts/vmtest.sh")?,
        Cmd::Lint => cargo_in(&repo, &["fmt", "--all", "--check"])?,
        Cmd::Proto => run_script(&repo, "scripts/gen-proto.sh")?,
        Cmd::SyncHome { dest } => sync_home(&repo, &dest)?,
    }

    Ok(())
}

fn repo_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .context("failed to derive repository root from xtask manifest dir")
}

fn build_bpf(repo: &Path) -> Result<()> {
    let out_dir = repo.join("bpf/out");
    std::fs::create_dir_all(&out_dir).context("failed to create bpf output directory")?;

    run(
        repo,
        &clang_binary(),
        &[
            "-O2",
            "-g",
            "-target",
            "bpf",
            "-D__TARGET_ARCH_x86",
            "-I",
            "bpf",
            "-I",
            "bpf/include",
            "-c",
            "bpf/kernelsentinel.bpf.c",
            "-o",
            "bpf/out/kernelsentinel.bpf.o",
        ],
    )?;

    run(
        repo,
        &clang_binary(),
        &[
            "-O2",
            "-g",
            "-target",
            "bpf",
            "-D__TARGET_ARCH_x86",
            "-I",
            "bpf",
            "-I",
            "bpf/include",
            "-c",
            "bpf/kernelsentinel_sched_ext.bpf.c",
            "-o",
            "bpf/out/kernelsentinel_sched_ext.bpf.o",
        ],
    )?;

    Ok(())
}

fn gen_skeletons(repo: &Path) -> Result<()> {
    write_stdout_to_file(
        repo,
        &bpftool_binary(),
        &[
            "gen",
            "skeleton",
            "bpf/out/kernelsentinel.bpf.o",
            "name",
            "kernelsentinel_bpf",
        ],
        &repo.join("daemon/src/kernelsentinel.skel.rs"),
    )
}

fn sync_home(repo: &Path, dest: &Path) -> Result<()> {
    run(repo, "rsync", &["-a", "--delete", "./", dest.to_str().unwrap_or_default()])
}

fn cargo_in(repo: &Path, args: &[&str]) -> Result<()> {
    run(repo, "cargo", args)
}

fn run_script(repo: &Path, script: &str) -> Result<()> {
    run(repo, "bash", &[script])
}

fn run(repo: &Path, program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .current_dir(repo)
        .status()
        .with_context(|| format!("failed to execute {program}"))?;

    if !status.success() {
        bail!("{program} exited with {status}");
    }

    Ok(())
}

fn write_stdout_to_file(repo: &Path, program: &str, args: &[&str], dest: &Path) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .current_dir(repo)
        .output()
        .with_context(|| format!("failed to execute {program}"))?;

    if !output.status.success() {
        bail!("{program} exited with {}", output.status);
    }

    std::fs::write(dest, output.stdout)
        .with_context(|| format!("failed to write {}", dest.display()))?;
    Ok(())
}

fn clang_binary() -> String {
    std::env::var("CLANG").unwrap_or_else(|_| "clang-17".to_string())
}

fn bpftool_binary() -> String {
    std::env::var("BPFTOOL").unwrap_or_else(|_| "bpftool".to_string())
}
