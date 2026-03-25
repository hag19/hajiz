pub mod capabilities;
pub mod filesystem;
pub mod namespaces;
pub mod seccomp;

use crate::error::HajizError;

#[derive(Debug, Clone)]
pub struct FilesystemRule {
	pub path: String,
	pub read_only: bool,
}

#[derive(Debug, Clone)]
pub struct IsolationConfig {
	pub disable_network: bool,
	pub drop_all_capabilities: bool,
	pub strict_seccomp: bool,
	pub use_seccomp_whitelist: bool,
	pub enable_hardening_filter: bool,
	pub seccomp_syscall_groups: Vec<String>,
	pub seccomp_allow_syscalls: Vec<String>,
	pub filesystem_rules: Vec<FilesystemRule>,
}

impl Default for IsolationConfig {
	fn default() -> Self {
		Self {
			disable_network: true,
			drop_all_capabilities: true,
			strict_seccomp: false,
			use_seccomp_whitelist: false,
			enable_hardening_filter: true,
			seccomp_syscall_groups: Vec::new(),
			seccomp_allow_syscalls: Vec::new(),
			filesystem_rules: Vec::new(),
		}
	}
}

pub fn apply_in_child(config: &IsolationConfig) -> Result<(), HajizError> {
	namespaces::setup_namespaces(config)?;
	capabilities::drop_capabilities(config)?;
	filesystem::setup_filesystem(config)?;
	seccomp::apply_seccomp(config)?;
	Ok(())
}
#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn default_config_is_core_isolation_only() {
		let config = IsolationConfig::default();
		assert!(config.disable_network);
		assert!(config.drop_all_capabilities);
		assert!(!config.use_seccomp_whitelist);
		assert!(config.enable_hardening_filter);
		assert!(config.seccomp_allow_syscalls.is_empty());
	}
}
