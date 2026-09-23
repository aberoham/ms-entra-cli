use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{EntraError, Result};

pub const DEFAULT_TENANT_ID: &str = "common";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default_account: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub clients: BTreeMap<String, ClientConfig>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub timezone: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientConfig {
    pub client_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tenant_id: String,
}

impl Config {
    pub fn load() -> Result<Self> {
        Self::load_from(&config_file_path()?)
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() {
            return Err(EntraError::message(format!(
                "config file {} is a symlink, refusing to load",
                path.display()
            )));
        }
        harden_file_permissions(path, &metadata)?;
        let contents = fs::read(path)?;
        serde_json::from_slice(&contents).map_err(Into::into)
    }

    pub fn save(&self) -> Result<()> {
        let dir = ensure_config_dirs()?;
        let data = serde_json::to_vec_pretty(self)?;
        atomic_write(&dir.join("config.json"), &data)
    }

    pub fn client_for(&self, email: &str) -> ClientConfig {
        let mut client = self.clients.get(email).cloned().unwrap_or_default();
        if client.tenant_id.is_empty() {
            client.tenant_id = DEFAULT_TENANT_ID.to_owned();
        }
        client
    }
}

pub fn config_dir() -> Result<PathBuf> {
    if let Some(value) = std::env::var_os("ENTRA_CONFIG_DIR") {
        return Ok(PathBuf::from(value));
    }
    dirs::config_dir()
        .map(|root| root.join("entra"))
        .ok_or_else(|| EntraError::message("could not determine the user configuration directory"))
}

pub fn accounts_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("accounts"))
}

pub fn config_file_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.json"))
}

pub fn ensure_config_dirs() -> Result<PathBuf> {
    let root = config_dir()?;
    for path in [&root, &root.join("accounts")] {
        fs::create_dir_all(path)?;
        set_mode(path, 0o700)?;
    }
    Ok(root)
}

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| EntraError::message("configuration path has no parent directory"))?;
    fs::create_dir_all(parent)?;
    let unique = format!(
        ".tmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let temporary = parent.join(unique);
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        set_mode(&temporary, 0o600)?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn harden_file_permissions(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            eprintln!(
                "warning: config file {} has permissions {:o}, expected 600; fixing",
                path.display(),
                mode
            );
            set_mode(path, 0o600)?;
        }
    }
    #[cfg(not(unix))]
    let _ = (path, metadata);
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn reads_the_stored_config_format() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(
            &path,
            br#"{"default_account":"person@example.test","clients":{"person@example.test":{"client_id":"client","tenant_id":"tenant"}}}"#,
        )
        .unwrap();
        let config = Config::load_from(&path).unwrap();
        assert_eq!(config.default_account, "person@example.test");
        assert_eq!(config.client_for("person@example.test").client_id, "client");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_config() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("config.json");
        fs::write(&target, b"{}").unwrap();
        symlink(&target, &link).unwrap();
        assert!(Config::load_from(&link)
            .unwrap_err()
            .to_string()
            .contains("symlink"));
    }
}
