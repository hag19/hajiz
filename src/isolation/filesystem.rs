use std::{
    ffi::CString,
    os::fd::RawFd,
};

use nix::libc;

use crate::{
    error::HajizError,
    isolation::{FilesystemRule, IsolationConfig},
};

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

const ACCESS_EXECUTE: u64 = 1 << 0;
const ACCESS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_READ_FILE: u64 = 1 << 2;
const ACCESS_READ_DIR: u64 = 1 << 3;

fn handled_access_mask() -> u64 {
    ACCESS_EXECUTE | ACCESS_WRITE_FILE | ACCESS_READ_FILE | ACCESS_READ_DIR
}

fn allowed_access_mask(rule: &FilesystemRule) -> u64 {
    if rule.read_only {
        ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_READ_DIR
    } else {
        ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_READ_DIR | ACCESS_WRITE_FILE
    }
}

pub fn setup_filesystem(config: &IsolationConfig) -> Result<(), HajizError> {
    if config.filesystem_rules.is_empty() {
        return Ok(());
    }

    let ruleset_fd = create_ruleset()?;

    for rule in &config.filesystem_rules {
        add_path_rule(ruleset_fd, rule)?;
    }

    let restrict_result = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0) };
    let close_result = unsafe { libc::close(ruleset_fd) };
    if close_result != 0 {
        let err = std::io::Error::last_os_error();
        return Err(HajizError::Isolation(format!(
            "failed to close Landlock ruleset fd: {err}"
        )));
    }

    if restrict_result != 0 {
        let err = std::io::Error::last_os_error();
        return Err(HajizError::Isolation(format!(
            "failed to enforce Landlock ruleset: {err}"
        )));
    }

    Ok(())
}

fn create_ruleset() -> Result<RawFd, HajizError> {
    let attr = LandlockRulesetAttr {
        handled_access_fs: handled_access_mask(),
    };

    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0,
        )
    };

    if result < 0 {
        let err = std::io::Error::last_os_error();
        return Err(HajizError::Isolation(format!(
            "failed to create Landlock ruleset (kernel may not support it): {err}"
        )));
    }

    Ok(result as RawFd)
}

fn add_path_rule(ruleset_fd: RawFd, rule: &FilesystemRule) -> Result<(), HajizError> {
    let c_path = CString::new(rule.path.clone())
        .map_err(|_| HajizError::Config(format!("invalid filesystem path '{}': contains NUL", rule.path)))?;

    let path_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if path_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(HajizError::Isolation(format!(
            "failed to open Landlock path '{}': {err}",
            rule.path
        )));
    }

    let attr = LandlockPathBeneathAttr {
        allowed_access: allowed_access_mask(rule),
        parent_fd: path_fd,
    };

    let add_result = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &attr as *const LandlockPathBeneathAttr,
            0,
        )
    };

    let close_result = unsafe { libc::close(path_fd) };
    if close_result != 0 {
        let err = std::io::Error::last_os_error();
        return Err(HajizError::Isolation(format!(
            "failed to close Landlock path fd for '{}': {err}",
            rule.path
        )));
    }

    if add_result != 0 {
        let err = std::io::Error::last_os_error();
        return Err(HajizError::Isolation(format!(
            "failed to add Landlock rule for '{}': {err}",
            rule.path
        )));
    }

    Ok(())
}
