use serde::Deserialize;

/// Configuration complète d'un profil de sandboxing
#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    /// Nom du profil (ex: "firefox", "untrusted")
    pub name: String,

    /// Description du profil
    pub description: Option<String>,

    /// Configuration réseau
    #[serde(default)]
    pub network: NetworkConfig,

    /// Configuration filesystem
    #[serde(default)]
    pub filesystem: FilesystemConfig,

    /// Configuration seccomp
    #[serde(default)]
    pub seccomp: SeccompConfig,
}

/// Configuration réseau du profil
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NetworkConfig {
    /// Désactiver le réseau (true par défaut)
    #[serde(default = "default_true")]
    pub disable: bool,
}

/// Configuration filesystem du profil
#[derive(Debug, Clone, Deserialize, Default)]
pub struct FilesystemConfig {
    /// Chemins autorisés en lecture seule
    #[serde(default)]
    pub read_only: Vec<String>,

    /// Chemins autorisés en lecture/écriture
    #[serde(default)]
    pub read_write: Vec<String>,
}

/// Configuration seccomp du profil
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SeccompConfig {
    /// Activer le mode strict
    #[serde(default)]
    pub strict: bool,

    /// Activer le mode allowlist
    #[serde(default)]
    pub whitelist: bool,

    /// Activer le filtre de durcissement
    #[serde(default = "default_true")]
    pub hardening: bool,

    /// Groupes de syscalls autorisés
    #[serde(default)]
    pub allow_groups: Vec<String>,

    /// Syscalls individuels autorisés
    #[serde(default)]
    pub allow_syscalls: Vec<String>,
}

fn default_true() -> bool {
    true
}