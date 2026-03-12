use std::{fs, path::Path};

use crate::{error::HagboxError, profile::schema::Profile};

pub fn load_profile(path: &Path) -> Result<Profile, HagboxError> {
    let raw = fs::read_to_string(path)?;
    let profile: Profile = toml::from_str(&raw)
        .map_err(|e| HagboxError::Config(format!("invalid profile TOML: {e}")))?;
    Ok(profile)
}
