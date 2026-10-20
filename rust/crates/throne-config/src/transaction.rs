use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::Command;

/// Stage a candidate config beside the target, check it using sing-box,
/// and atomically rename only after successful validation.
/// Caller remains responsible for restarting the service and rollback on runtime failure.
/// A single-writer lock must be enforced by the caller.
pub fn validate_and_stage(
    target: &Path,
    config: &serde_json::Value,
    sing_box: &Path,
) -> Result<(), String> {
    let parent = target.parent().ok_or("target must have parent directory")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let candidate = target.with_extension("candidate");
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&candidate)
            .map_err(|e| format!("candidate already exists or cannot be created: {e}"))?;
        let bytes = serde_json::to_vec_pretty(config).map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);
        let status = Command::new(sing_box).arg("check").arg("-c").arg(&candidate)
            .status().map_err(|e| format!("cannot run sing-box check: {e}"))?;
        if !status.success() {
            return Err(format!("sing-box check failed: {status}"));
        }
        fs::rename(&candidate, target).map_err(|e| e.to_string())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&candidate);
    }
    result
}
