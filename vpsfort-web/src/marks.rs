//! The admins' marks: which abuse reports were mailed (and when, with the sources that
//! counted as reported), and which attention problems were seen. Kept by the console, so
//! every admin and every browser sees the same, and a restart forgets nothing; without a
//! `STATE_DIR` they live in memory. An object the page owns: the console stores it whole,
//! bounded in size, and hands it back as it is.

use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::{json, Value};

/// The marks object at most (the page keeps a few hundred entries).
pub const MAX_BYTES: usize = 256 * 1024;

pub struct Marks {
    inner: Mutex<Value>,
    path: Option<PathBuf>,
}

impl Marks {
    pub fn new(dir: Option<&std::path::Path>) -> Self {
        let path = dir.map(|d| d.join("marks.json"));
        let loaded = path.as_deref().and_then(crate::store::load).filter(Value::is_object).unwrap_or_else(|| json!({}));
        Marks { inner: Mutex::new(loaded), path }
    }

    pub fn get(&self) -> Value {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Replaces the marks with `v` (an object), and writes them.
    pub fn set(&self, v: Value) -> Result<(), &'static str> {
        if !v.is_object() {
            return Err("the marks must be a JSON object");
        }
        if serde_json::to_vec(&v).map_or(true, |b| b.len() > MAX_BYTES) {
            return Err("the marks are too large");
        }
        // written under the lock: two admins' marks at once would write the same temporary
        // file, and a mix of the two would be renamed into place
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        *inner = v;
        if let Some(p) = &self.path {
            crate::store::save(p, &inner);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_on_disk_and_bounded() {
        let d = std::env::temp_dir().join(format!("lgw-marks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let m = Marks::new(Some(&d));
        assert_eq!(m.get(), json!({}));
        m.set(json!({"reported": {"AS64496": {"at": 1}}})).unwrap();
        assert_eq!(Marks::new(Some(&d)).get()["reported"]["AS64496"]["at"], 1, "read back after a restart");
        assert!(m.set(json!([1])).is_err());
        assert!(m.set(json!({"x": "y".repeat(MAX_BYTES)})).is_err());
        let memory = Marks::new(None);
        memory.set(json!({"a": 1})).unwrap();
        assert_eq!(memory.get()["a"], 1);
        let _ = std::fs::remove_dir_all(&d);
    }
}
