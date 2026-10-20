use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSetSpec {
    pub source_name: String,
    pub tag: String,
    pub path: PathBuf,
}

pub fn validate_specs(specs: &[RuleSetSpec], cache_root: &Path) -> Result<(), String> {
    let mut names = HashSet::new();
    let mut tags = HashSet::new();
    for spec in specs {
        if spec.source_name.is_empty() || spec.tag.is_empty() ||
            !names.insert(&spec.source_name) || !tags.insert(&spec.tag) {
            return Err("empty or duplicate rule-set name/tag".into());
        }
        // Paths are fixed relative filenames, not user-controlled absolute paths.
        if spec.path.components().count() != 1 ||
            spec.path.extension().and_then(|x| x.to_str()) != Some("srs") {
            return Err(format!("invalid local rule-set filename: {:?}", spec.path));
        }
        let full = cache_root.join(&spec.path);
        let meta = std::fs::symlink_metadata(&full).map_err(|e| format!("{}: {e}", full.display()))?;
        if !meta.file_type().is_file() || meta.len() == 0 {
            return Err(format!("missing or invalid SRS file: {}", full.display()));
        }
    }
    Ok(())
}

pub fn tag_map(specs: &[RuleSetSpec]) -> HashMap<String, String> {
    specs.iter().map(|s| (s.source_name.clone(), s.tag.clone())).collect()
}

pub fn local_definitions(specs: &[RuleSetSpec], cache_root: &Path) -> Vec<Value> {
    specs.iter().map(|s| json!({
        "type": "local", "tag": s.tag, "format": "binary",
        "path": cache_root.join(&s.path).to_string_lossy()
    })).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_traversal() {
        let spec = RuleSetSpec { source_name: "ru".into(), tag: "ru".into(), path: "../evil.srs".into() };
        assert!(validate_specs(&[spec], Path::new("/tmp")).is_err());
    }
}
