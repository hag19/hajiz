use clap::{CommandFactory, Parser};
use hajiz::{
    isolation::{FilesystemRule, IsolationConfig},
    kernel::KernelCapabilities,
    profile::load_profile,
    runtime::process::{SandboxProcess, SpawnOptions},
    telemetry::{SecurityEvent, TelemetryLogger},
};
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Parser, Debug)]
#[command(name = "hajiz", version, about, arg_required_else_help = true)]
struct Cli {
    #[arg(long)]
    kernel_info: bool,
    #[arg(long, value_name = "FICHIER")]
    profile: Option<PathBuf>,
    #[arg(long, value_name = "FICHIER")]
    log: Option<PathBuf>,
    #[arg(long)]
    allow_net: bool,
    #[arg(long)]
    keep_caps: bool,
    #[arg(long)]
    strict_seccomp: bool,
    #[arg(long)]
    seccomp_whitelist: bool,
    #[arg(long)]
    no_hardening: bool,
    #[arg(long = "allow-group", value_name = "GROUPE")]
    syscall_groups: Vec<String>,
    #[arg(long = "allow-syscall", value_name = "SYSCALL")]
    allow_syscalls: Vec<String>,
    #[arg(long = "fs", value_name = "CHEMIN:MODE")]
    fs_rules: Vec<String>,
    #[arg(short, long)]
    verbose: bool,
    #[arg(required = false)]
    binary: Option<String>,
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,
}

fn parse_fs_rule(s: &str) -> Option<FilesystemRule> {
    let (path, mode) = s.rsplit_once(':')?;
    let read_only = match mode {
        "ro" => true,
        "rw" => false,
        _ => return None,
    };
    Some(FilesystemRule { path: path.to_string(), read_only })
}

fn main() {
    if std::env::args().any(|a| a == "--help" || a == "-h") {
        Cli::command().print_help().unwrap();
        println!();
        std::process::exit(0);
    }
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("hajiz {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    let cli = Cli::parse();

    if cli.kernel_info {
        match KernelCapabilities::detect() {
            Some(caps) => println!("{}", caps.report()),
            None => eprintln!("[hajiz] impossible de détecter la version kernel"),
        }
        std::process::exit(0);
    }

    let binary_str = match &cli.binary {
        Some(b) => b.clone(),
        None => {
            eprintln!("[hajiz] erreur: un binaire est requis");
            std::process::exit(2);
        }
    };

    let logger = match &cli.log {
        Some(path) => TelemetryLogger::with_file(path.clone(), cli.verbose),
        None => TelemetryLogger::new(cli.verbose),
    };

    let mut config = IsolationConfig {
        disable_network: !cli.allow_net,
        drop_all_capabilities: !cli.keep_caps,
        strict_seccomp: cli.strict_seccomp,
        use_seccomp_whitelist: cli.seccomp_whitelist,
        enable_hardening_filter: !cli.no_hardening,
        seccomp_syscall_groups: cli.syscall_groups,
        seccomp_allow_syscalls: cli.allow_syscalls,
        filesystem_rules: Vec::new(),
    };

    let profile_name = if let Some(profile_path) = &cli.profile {
        match load_profile(profile_path) {
            Ok(profile) => {
                let name = profile.name.clone();
                if !cli.allow_net {
                    config.disable_network = profile.network.disable;
                }
                for path in &profile.filesystem.read_only {
                    config.filesystem_rules.push(FilesystemRule { path: path.clone(), read_only: true });
                }
                for path in &profile.filesystem.read_write {
                    config.filesystem_rules.push(FilesystemRule { path: path.clone(), read_only: false });
                }
                config.seccomp_syscall_groups.extend(profile.seccomp.allow_groups);
                config.seccomp_allow_syscalls.extend(profile.seccomp.allow_syscalls);
                Some(name)
            }
            Err(e) => {
                eprintln!("[hajiz] erreur chargement profil: {e}");
                std::process::exit(2);
            }
        }
    } else {
        None
    };

    for rule_str in &cli.fs_rules {
        match parse_fs_rule(rule_str) {
            Some(rule) => config.filesystem_rules.push(rule),
            None => {
                eprintln!("[hajiz] valeur --fs invalide '{}': attendu CHEMIN:ro ou CHEMIN:rw", rule_str);
                std::process::exit(2);
            }
        }
    }

    let policy_hash = TelemetryLogger::policy_hash(&config);
    if cli.verbose {
        eprintln!("[hajiz] hash politique: {}", policy_hash);
    }

    let binary = PathBuf::from(&binary_str);

    logger.log(&SecurityEvent::SandboxStarted {
        pid: std::process::id(),
        binary: binary_str.clone(),
        profile: profile_name,
        timestamp: SystemTime::now(),
    });

    let result = SandboxProcess::spawn(SpawnOptions {
        binary,
        args: cli.args,
        verbose: cli.verbose,
        isolation: config,
    })
    .and_then(|sandbox| {
        let pid = sandbox.pid;
        sandbox.monitor().map(|status| {
            logger.log(&SecurityEvent::SandboxExited {
                pid,
                exit_code: status.code().unwrap_or(-1),
                timestamp: SystemTime::now(),
            });
            if !status.success() {
                std::process::exit(status.code().unwrap_or(1));
            }
        })
    });

    if let Err(e) = result {
        eprintln!("[hajiz] erreur: {e}");
        std::process::exit(1);
    }
}
