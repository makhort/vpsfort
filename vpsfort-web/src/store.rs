//! The console's own state on disk (`STATE_DIR`, the unit's `StateDirectory`): the attention
//! history, the nodes' digests and the admins' marks survive a restart there. Small JSON
//! files, written whole and renamed into place; readable by the service user only. Nothing
//! of the nodes' data is kept here beyond the digests' text.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// The file's JSON, if it is there and parses (a damaged file is set aside, not read).
pub fn load(path: &Path) -> Option<Value> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice(&bytes) {
        Ok(v) => Some(v),
        Err(e) => {
            let aside = path.with_extension(format!("bad-{}", crate::time::now() / crate::time::SEC));
            let _ = std::fs::rename(path, &aside);
            crate::say!("vpsfort-web: {} is not JSON ({e}): kept aside as {}", path.display(), aside.display());
            None
        }
    }
}

/// Writes the JSON atomically, mode 0600; a failure is logged once per file and path.
pub fn save(path: &Path, value: &Value) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("json.tmp");
    let write = || -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(&serde_json::to_vec(value)?)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    if let Err(e) = write() {
        static SAID: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());
        let mut said = SAID.lock().unwrap_or_else(|e| e.into_inner());
        if !said.contains(&path.to_path_buf()) {
            said.push(path.to_path_buf());
            crate::say!("vpsfort-web: cannot write {}: {e} (its state lives in memory until this works)", path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_and_loads_and_sets_damage_aside() {
        let d = std::env::temp_dir().join(format!("lgw-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let p = d.join("x.json");
        save(&p, &serde_json::json!({"a": 1}));
        assert_eq!(load(&p), Some(serde_json::json!({"a": 1})));
        std::fs::write(&p, "{not json").unwrap();
        assert_eq!(load(&p), None);
        assert!(!p.exists(), "the damaged file is set aside");
        assert!(std::fs::read_dir(&d).unwrap().flatten().any(|e| e.file_name().to_string_lossy().starts_with("x.bad-")));
        assert_eq!(load(&d.join("missing.json")), None);
        let _ = std::fs::remove_dir_all(&d);
    }
}
