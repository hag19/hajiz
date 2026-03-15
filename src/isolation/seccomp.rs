use std::collections::BTreeSet;

use libseccomp::{
    ScmpAction,
    ScmpFilterContext,
    ScmpSyscall,
};
use nix::libc;

use crate::{error::HajizError, isolation::IsolationConfig};

pub fn apply_seccomp(config: &IsolationConfig) -> Result<(), HajizError> {
    if config.use_seccomp_whitelist {
        apply_whitelist_filter(config)?;
        return Ok(());
    }

    if config.enable_hardening_filter {
        apply_hardening_filter()?;
        return Ok(());
    }

    if config.strict_seccomp {
        let result = unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_STRICT, 0, 0, 0) };
        if result != 0 {
            let err = std::io::Error::last_os_error();
            return Err(HajizError::Isolation(format!(
                "failed to enable strict seccomp mode: {err}"
            )));
        }
    }

    Ok(())
}

fn apply_hardening_filter() -> Result<(), HajizError> {
    // Default-allow, then deny high-risk primitives often used to expand privilege
    // or escape sandboxes when user namespaces are available.
    let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow)
        .map_err(|e| HajizError::Isolation(format!("failed to create hardening seccomp filter: {e}")))?;

    for syscall_name in hardened_denied_syscalls() {
        let syscall = ScmpSyscall::from_name(syscall_name)
            .map_err(|_| HajizError::Config(format!("unknown hardening syscall name: {syscall_name}")))?;
        filter
            .add_rule(ScmpAction::Errno(libc::EPERM), syscall)
            .map_err(|e| HajizError::Isolation(format!(
                "failed to add hardening seccomp rule for {syscall_name}: {e}"
            )))?;
    }

    filter
        .load()
        .map_err(|e| HajizError::Isolation(format!("failed to load hardening seccomp filter: {e}")))?;

    Ok(())
}

fn hardened_denied_syscalls() -> &'static [&'static str] {
    &[
        "unshare",
        "setns",
        "clone3",
        "bpf",
        "userfaultfd",
        "add_key",
        "request_key",
        "keyctl",
    ]
}

fn apply_whitelist_filter(config: &IsolationConfig) -> Result<(), HajizError> {
    let allowed = resolve_allowed_syscalls(config);

    let mut filter = ScmpFilterContext::new_filter(ScmpAction::Errno(libc::EPERM))
        .map_err(|e| HajizError::Isolation(format!("failed to create seccomp filter: {e}")))?;

    for syscall_name in allowed {
        let syscall = ScmpSyscall::from_name(&syscall_name)
            .map_err(|_| HajizError::Config(format!("unknown syscall in seccomp policy: {syscall_name}")))?;
        filter
            .add_rule(ScmpAction::Allow, syscall)
            .map_err(|e| HajizError::Isolation(format!("failed to add seccomp rule for {syscall_name}: {e}")))?;
    }

    filter
        .load()
        .map_err(|e| HajizError::Isolation(format!("failed to load seccomp filter: {e}")))?;

    Ok(())
}

pub(crate) fn resolve_allowed_syscalls(config: &IsolationConfig) -> BTreeSet<String> {
    resolve_allowed_syscalls_from_policy(
        &config.seccomp_syscall_groups,
        &config.seccomp_allow_syscalls,
    )
}

pub fn resolve_allowed_syscalls_from_policy(
    groups: &[String],
    explicit_allow: &[String],
) -> BTreeSet<String> {
    let mut allowed: BTreeSet<String> = baseline_syscalls()
        .into_iter()
        .map(|name| name.to_string())
        .collect();

    for group in groups {
        for syscall_name in syscall_group(group) {
            allowed.insert(syscall_name.to_string());
        }
    }

    for syscall_name in explicit_allow {
        allowed.insert(syscall_name.to_string());
    }

    allowed
}

fn baseline_syscalls() -> BTreeSet<&'static str> {
    [
        "read",
        "write",
        "close",
        "fstat",
        "newfstatat",
        "lseek",
        "mmap",
        "mprotect",
        "munmap",
        "brk",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "futex",
        "set_tid_address",
        "set_robust_list",
        "arch_prctl",
        "prlimit64",
        "clock_gettime",
        "getrandom",
        "getpid",
        "gettid",
        "exit",
        "exit_group",
        "execve",
        "execveat",
        "openat",
        "access",
    ]
    .into_iter()
    .collect()
}

fn syscall_group(group: &str) -> &'static [&'static str] {
    match group {
        "io" => &["open", "openat", "close", "read", "write", "lseek", "fstat", "newfstatat", "stat"],
        "memory" => &["mmap", "mprotect", "munmap", "brk", "madvise"],
        "threading" => &["clone", "clone3", "futex", "set_tid_address", "set_robust_list"],
        "network" => &["socket", "connect", "sendto", "sendmsg", "recvfrom", "recvmsg", "bind", "listen", "accept", "accept4"],
        "process" => &["fork", "vfork", "execve", "execveat", "wait4", "waitid", "kill", "getpid"],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_seccomp,
        resolve_allowed_syscalls,
    };
    use nix::{
        libc,
        sys::wait::{
            waitpid,
            WaitStatus,
        },
        unistd::{
            fork,
            ForkResult,
        },
    };
    use crate::isolation::IsolationConfig;

    fn config_with_groups(groups: &[&str]) -> IsolationConfig {
        IsolationConfig {
            use_seccomp_whitelist: true,
            seccomp_syscall_groups: groups.iter().map(|g| g.to_string()).collect(),
            ..IsolationConfig::default()
        }
    }

    #[test]
    fn network_group_adds_socket_calls() {
        let config = config_with_groups(&["network"]);
        let allowed = resolve_allowed_syscalls(&config);
        assert!(allowed.contains("socket"));
        assert!(allowed.contains("connect"));
    }

    #[test]
    fn no_network_group_keeps_socket_denied() {
        let config = config_with_groups(&["io", "memory", "threading", "process"]);
        let allowed = resolve_allowed_syscalls(&config);
        assert!(!allowed.contains("socket"));
        assert!(!allowed.contains("connect"));
    }

    #[test]
    fn explicit_allow_adds_known_syscall() {
        let mut config = config_with_groups(&[]);
        config.seccomp_allow_syscalls = vec!["wait4".to_string()];
        let allowed = resolve_allowed_syscalls(&config);
        assert!(allowed.contains("wait4"));
    }

    #[test]
    fn runtime_seccomp_blocks_socket_without_network_group() {
        let config = config_with_groups(&["io", "memory", "threading", "process"]);
        let exit_code = run_socket_probe_under_seccomp(config);
        assert_eq!(exit_code, 0, "expected socket to be denied with EPERM");
    }

    #[test]
    fn runtime_seccomp_allows_socket_with_network_group() {
        let config = config_with_groups(&["io", "memory", "threading", "process", "network"]);
        let exit_code = run_socket_probe_under_seccomp(config);
        assert_eq!(exit_code, 0, "expected socket to be allowed with network group");
    }

    #[test]
    fn hardening_profile_blocks_namespace_entry_syscalls() {
        let denied = super::hardened_denied_syscalls();
        assert!(denied.contains(&"unshare"));
        assert!(denied.contains(&"setns"));
        assert!(denied.contains(&"clone3"));
    }

    fn run_socket_probe_under_seccomp(mut config: IsolationConfig) -> i32 {
        config.use_seccomp_whitelist = true;

        let fork_result = unsafe { fork() }.expect("fork should succeed");
        match fork_result {
            ForkResult::Parent { child } => {
                match waitpid(child, None).expect("waitpid should succeed") {
                    WaitStatus::Exited(_, code) => code,
                    other => panic!("unexpected child status: {other:?}"),
                }
            }
            ForkResult::Child => {
                let outcome = child_socket_probe(config);
                unsafe {
                    libc::_exit(outcome);
                }
            }
        }
    }

    fn child_socket_probe(config: IsolationConfig) -> i32 {
        if apply_seccomp(&config).is_err() {
            return 2;
        }

        let socket_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if config.seccomp_syscall_groups.iter().any(|group| group == "network") {
            if socket_fd >= 0 {
                unsafe {
                    libc::close(socket_fd);
                }
                return 0;
            }
            return 3;
        }

        if socket_fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                return 0;
            }
            return 4;
        }

        unsafe {
            libc::close(socket_fd);
        }
        5
    }
}
