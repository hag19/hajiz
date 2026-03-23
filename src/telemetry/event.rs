use std::time::SystemTime;

/// Types d'événements de sécurité émis par le sandbox
#[derive(Debug, Clone)]
pub enum SecurityEvent {
    /// Sandbox démarré
    SandboxStarted {
        pid: u32,
        binary: String,
        profile: Option<String>,
        timestamp: SystemTime,
    },
    /// Syscall refusé par seccomp
    SyscallDenied {
        pid: u32,
        syscall: String,
        timestamp: SystemTime,
    },
    /// Accès filesystem refusé
    FilesystemDenied {
        pid: u32,
        path: String,
        timestamp: SystemTime,
    },
    /// Sandbox terminé
    SandboxExited {
        pid: u32,
        exit_code: i32,
        timestamp: SystemTime,
    },
}

impl SecurityEvent {
    /// Retourne le timestamp de l'événement
    pub fn timestamp(&self) -> SystemTime {
        match self {
            Self::SandboxStarted { timestamp, .. } => *timestamp,
            Self::SyscallDenied { timestamp, .. } => *timestamp,
            Self::FilesystemDenied { timestamp, .. } => *timestamp,
            Self::SandboxExited { timestamp, .. } => *timestamp,
        }
    }

    /// Retourne le nom de l'événement
    pub fn name(&self) -> &str {
        match self {
            Self::SandboxStarted { .. } => "sandbox_started",
            Self::SyscallDenied { .. } => "syscall_denied",
            Self::FilesystemDenied { .. } => "filesystem_denied",
            Self::SandboxExited { .. } => "sandbox_exited",
        }
    }

    /// Formate l'événement en JSON simple
    pub fn to_json(&self) -> String {
        let ts = self
            .timestamp()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match self {
            Self::SandboxStarted { pid, binary, profile, .. } => {
                let profile_str = profile
                    .as_deref()
                    .map(|p| format!("\"{}\"", p))
                    .unwrap_or_else(|| "null".to_string());
                format!(
                    r#"{{"event":"sandbox_started","pid":{pid},"binary":"{binary}","profile":{profile_str},"timestamp":{ts}}}"#
                )
            }
            Self::SyscallDenied { pid, syscall, .. } => {
                format!(
                    r#"{{"event":"syscall_denied","pid":{pid},"syscall":"{syscall}","timestamp":{ts}}}"#
                )
            }
            Self::FilesystemDenied { pid, path, .. } => {
                format!(
                    r#"{{"event":"filesystem_denied","pid":{pid},"path":"{path}","timestamp":{ts}}}"#
                )
            }
            Self::SandboxExited { pid, exit_code, .. } => {
                format!(
                    r#"{{"event":"sandbox_exited","pid":{pid},"exit_code":{exit_code},"timestamp":{ts}}}"#
                )
            }
        }
    }
}