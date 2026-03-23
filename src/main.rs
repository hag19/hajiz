use clap::{CommandFactory, Parser};
use hajiz::{
    isolation::{FilesystemRule, IsolationConfig},
    profile::load_profile,
    runtime::process::{SandboxProcess, SpawnOptions},
    telemetry::{SecurityEvent, TelemetryLogger},
};
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Parser, Debug)]
#[command(name = "hajiz", version, about, arg_required_else_help = true)]
struct Cli {
    /// Charger un profil TOML
    #[arg(long, value_name = "FICHIER")]
    profile: Option<PathBuf>,

    /// Fichier de log pour la télémétrie
    #[arg(long, value_name = "FICHIER")]
    log: Option<PathBuf>,

    /// Autoriser l'accès réseau (désactivé par défaut)
    #[arg(long)]
    allow_net: bool,

    /// Conserver les capabilities (supprimées par défaut)
    #[arg(long)]
    keep_caps: bool,

    /// Activer le mode seccomp strict
    #[arg(long)]
    strict_seccomp: bool,

    /// Activer le mode allowlist seccomp
    #[arg(long)]
    seccomp_whitelist: bool,

    /// Désactiver le filtre seccomp de durcissement
    #[arg(long)]
    no_hardening: bool,

    /// Autoriser un groupe de syscalls
    #[arg(long = "allow-group", value_name = "GROUPE")]
    syscall_groups: Vec<String>,

    /// Autoriser un syscall spécifique par nom
    #[arg(long = "allow-syscall", value_name = "SYSCALL")]
    allow_syscalls: Vec<String>,

    /// Ajouter une règle filesystem: chemin:ro ou chemin:rw
    #[arg(long = "fs", value_name = "CHEMIN:MODE")]
    fs_rules: Vec<String>,

    /// Mode verbeux
    #[arg(short, long)]
    verbose: bool,

    /// Binaire à exécuter dans le sandbox
    #[arg(required = true)]
    binary: String,

    /// Arguments à passer au binaire
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

    // Initialisation du logger de télémétrie
    let logger = match &cli.log {
        Some(path) => TelemetryLogger::with_file(path.clone(), cli.verbose),
        None => TelemetryLogger::new(cli.verbose),
    };

    // Construction de la config de base depuis les flags CLI
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

    // Appliquer le profil TOML si fourni
    let profile_name = if let Some(profile_path) = &cli.profile {
        match load_profile(profile_path) {
            Ok(profile) => {
                let name = profile.name.clone();
                if !cli.allow_net {
                    config.disable_network = profile.network.disable;
                }
                for path in &profile.filesystem.read_only {
                    config.filesystem_rules.push(FilesystemRule {
                        path: path.clone(),
                        read_only: true,
                    });
                }
                for path in &profile.filesystem.read_write {
                    config.filesystem_rules.push(FilesystemRule {
                        path: path.clone(),
                        read_only: false,
                    });
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

    // Ajouter les règles --fs après le profil
    for rule_str in &cli.fs_rules {
        match parse_fs_rule(rule_str) {
            Some(rule) => config.filesystem_rules.push(rule),
            None => {
                eprintln!("[hajiz] valeur --fs invalide '{}': attendu CHEMIN:ro ou CHEMIN:rw", rule_str);
                std::process::exit(2);
            }
        }
    }

    // Log hash de la politique
    let policy_hash = TelemetryLogger::policy_hash(&config);
    if cli.verbose {
        eprintln!("[hajiz] hash politique: {}", policy_hash);
    }

    let binary = PathBuf::from(&cli.binary);

    // Événement démarrage sandbox
    logger.log(&SecurityEvent::SandboxStarted {
        pid: std::process::id(),
        binary: cli.binary.clone(),
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
            // Événement fin sandbox
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