use nix::{
    mount::{mount, MsFlags},
    sched::{unshare, CloneFlags},
};

use crate::{error::HajizError, isolation::IsolationConfig};

pub fn setup_namespaces(config: &IsolationConfig) -> Result<(), HajizError> {
    let mut flags = CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWIPC | CloneFlags::CLONE_NEWUTS;
    if config.disable_network {
        flags |= CloneFlags::CLONE_NEWNET;
    }

    unshare(flags)
        .map_err(|e| HajizError::Isolation(format!("failed to unshare namespaces: {e}")))?;

    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| HajizError::Isolation(format!("failed to set mount propagation: {e}")))?;

    Ok(())
}