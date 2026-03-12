use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "hagbox")]
#[command(about = "Default-deny application sandbox for Linux")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Launch a binary inside the sandbox
    Run(RunArgs),
    /// Kill a running sandbox by PID or name
    Kill(KillArgs),
    /// List all running sandboxed processes
    List,
}

/// Arguments for the `run` subcommand
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Path to a TOML profile (e.g. profiles/untrusted.toml)
    #[arg(long, value_name = "FILE")]
    pub profile: Option<PathBuf>,

    /// Disable all network access
    #[arg(long)]
    pub no_net: bool,

    /// Paranoid mode: only /tmp rw, no network, minimal syscalls
    #[arg(long)]
    pub paranoid: bool,

    /// Whitelist a filesystem path in <path>:<rw|ro> format (repeatable)
    #[arg(long = "fs", value_name = "PATH:ACCESS")]
    pub fs: Vec<String>,

    /// Comma-separated list of additional allowed syscalls
    #[arg(long, value_name = "SYSCALLS")]
    pub allow: Option<String>,

    /// Human-readable name for this sandbox (used with `kill <name>`)
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Print sandbox setup steps
    #[arg(long, short)]
    pub verbose: bool,

    /// Binary to execute inside the sandbox
    #[arg(value_name = "BINARY")]
    pub binary: PathBuf,

    /// Arguments forwarded to the binary
    #[arg(value_name = "ARGS", trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

/// Arguments for the `kill` subcommand
#[derive(Debug, Args)]
pub struct KillArgs {
    /// PID (number) or name (string) of the sandbox to kill
    pub target: String,

    /// Skip SIGTERM and send SIGKILL immediately
    #[arg(long, short)]
    pub force: bool,
}
