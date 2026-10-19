use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use serde_json::Value;

const PREFIX: &str = "throne://route/";
const MAX_ENCODED_BYTES: usize = 1_000_000;

#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    pub name: Option<String>,
    pub kind: Option<String>,
    pub v: Option<u64>,
    pub default_outbound: String,
    pub rules: Vec<Value>,
}

#[derive(Debug)]
pub enum ImportError {
    InvalidUri,
    TooLarge,
    InvalidBase64,
    InvalidJson,
    InvalidProfile,
}

pub fn import_uri(uri: &str) -> Result<Profile, ImportError> {
    let payload = uri.trim().strip_prefix(PREFIX).ok_or(ImportError::InvalidUri)?;
    if payload.is_empty() || payload.contains(['?', '#', '/']) {
        return Err(ImportError::InvalidUri);
    }
    if payload.len() > MAX_ENCODED_BYTES {
        return Err(ImportError::TooLarge);
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| ImportError::InvalidBase64)?;
    let profile: Profile = serde_json::from_slice(&bytes).map_err(|_| ImportError::InvalidJson)?;
    if profile.kind.as_deref().is_some_and(|k| k != "throne-route-profile") {
        return Err(ImportError::InvalidProfile);
    }
    if profile.v.is_some_and(|v| v != 1) || profile.default_outbound.is_empty() {
        return Err(ImportError::InvalidProfile);
    }
    Ok(profile)
}
