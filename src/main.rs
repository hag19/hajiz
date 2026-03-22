use clap::{CommandFactory, Parser};
use hajiz::{
    isolation::{FilesystemRule, IsolationConfig},
    runtime::process::{SandboxProcess, SpawnOptions},
};

#[derive(Parser, Debug)]
#[command(name = "hajiz", version, about, arg_required_else_help = true)]
struct Cli {
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
    #[arg(required = true)]
    binary: String,
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

    let mut filesystem_rules = Vec::new();
    for rule_str in &cli.fs_rules {
        match parse_fs_rule(rule_str) {
            Some(rule) => filesystem_rules.push(rule),
            None => {
                eprintln!("[hajiz] valeur --fs invalide '{}': attendu CHEMIN:ro ou CHEMIN:rw", rule_str);
                std::process::exit(2);
            }
        }
    }

    let config = IsolationConfig {
        disable_network: !cli.allow_net,
        drop_all_capabilities: !cli.keep_caps,
        strict_seccomp: cli.strict_seccomp,
        use_seccomp_whitelist: cli.seccomp_whitelist,
        enable_hardening_filter: !cli.no_hardening,
        seccomp_syscall_groups: cli.syscall_groups,
        seccomp_allow_syscalls: cli.allow_syscalls,
        filesystem_rules,
    };

    let binary = std::path::PathBuf::from(&cli.binary);

    let result = SandboxProcess::spawn(SpawnOptions {
        binary,
        args: cli.args,
        verbose: cli.verbose,
        isolation: config,
    })
    .and_then(|sandbox| {
        sandbox.monitor().map(|status| {
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
