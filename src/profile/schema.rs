use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Profile {
    pub filesystem: Option<FilesystemConfig>,
    pub syscalls: Option<SyscallsConfig>,
    pub network: Option<NetworkConfig>,
    pub capabilities: Option<CapabilitiesConfig>,
    pub resources: Option<ResourcesConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemConfig {
    pub mode: Option<String>,
    pub mounts: Option<Vec<MountEntry>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountEntry {
    pub path: String,
    pub access: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallsConfig {
    pub mode: Option<String>,
    pub allow_groups: Option<Vec<String>>,
    pub allow: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitiesConfig {
    pub allow: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesConfig {
    pub max_memory: Option<String>,
    pub max_cpu: Option<String>,
    pub max_procs: Option<u32>,
    pub timeout: Option<String>,
}
