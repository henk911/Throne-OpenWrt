use serde_json::{json, Map, Value};
use crate::throne_import::Profile;

#[derive(Debug, PartialEq, Eq)]
pub enum ConvertError {
    UnsupportedRule(usize),
    UnsupportedAction(usize),
    InvalidRule(usize),
    UnknownOutbound(String),
}

/// Convert only explicitly supported route rules.
/// Any unsupported rule rejects the entire profile rather than silently changing policy.
/// The caller must supply actual configured outbound tags.
pub fn convert(profile: &Profile, proxy_tag: &str, direct_tag: &str) -> Result<Value, ConvertError> {
    if proxy_tag.is_empty() || direct_tag.is_empty() || proxy_tag == direct_tag {
        return Err(ConvertError::UnknownOutbound("invalid outbound tags".into()));
    }
    let outbound = |name: &str| -> Result<String, ConvertError> {
        match name {
            "proxy" => Ok(proxy_tag.to_owned()),
            "direct" => Ok(direct_tag.to_owned()),
            other => Err(ConvertError::UnknownOutbound(other.to_owned())),
        }
    };
    let final_tag = outbound(&profile.default_outbound)?;
    let mut rules = Vec::new();
    for (index, source) in profile.rules.iter().enumerate() {
        let obj = source.as_object().ok_or(ConvertError::InvalidRule(index))?;
        if obj.get("type").and_then(Value::as_str) != Some("custom") {
            return Err(ConvertError::UnsupportedRule(index));
        }
        let action = obj.get("action").and_then(Value::as_str).unwrap_or("route");
        // These keys are the complete supported input schema for this initial converter.
        let allowed = ["name", "type", "action", "outbound", "domain", "domain_suffix", "domain_keyword", "ip_cidr", "ip_is_private"];
        if obj.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(ConvertError::UnsupportedRule(index));
        }
        if action != "route" {
            return Err(ConvertError::UnsupportedAction(index));
        }
        let dest = obj.get("outbound").and_then(Value::as_str).ok_or(ConvertError::InvalidRule(index))?;
        let tag = outbound(dest)?;
        let mut result = Map::new();
        let mut matches = 0;
        for key in ["domain", "domain_suffix", "domain_keyword", "ip_cidr"] {
            if let Some(value) = obj.get(key) {
                let list = value.as_array().ok_or(ConvertError::InvalidRule(index))?;
                if list.is_empty() || !list.iter().all(Value::is_string) {
                    return Err(ConvertError::InvalidRule(index));
                }
                result.insert(key.to_string(), value.clone());
                matches += 1;
            }
        }
        if let Some(value) = obj.get("ip_is_private") {
            if value != &Value::Bool(true) {
                return Err(ConvertError::InvalidRule(index));
            }
            result.insert("ip_is_private".into(), value.clone());
            matches += 1;
        }
        if matches == 0 {
            return Err(ConvertError::InvalidRule(index));
        }
        result.insert("action".into(), json!("route"));
        result.insert("outbound".into(), json!(tag));
        rules.push(Value::Object(result));
    }
    Ok(json!({"route": {"rules": rules, "final": final_tag}}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::throne_import::import_uri;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    fn profile(value: Value) -> Profile {
        let encoded = URL_SAFE_NO_PAD.encode(value.to_string());
        import_uri(&format!("throne://route/{encoded}")).unwrap()
    }

    #[test]
    fn direct_domain_rule() {
        let p = profile(json!({"default_outbound":"proxy","rules":[
            {"type":"custom","action":"route","outbound":"direct","domain_suffix":["ru"]}
        ]}));
        let out = convert(&p, "vpn", "direct").unwrap();
        assert_eq!(out["route"]["final"], "vpn");
        assert_eq!(out["route"]["rules"][0]["domain_suffix"][0], "ru");
        assert_eq!(out["route"]["rules"][0]["outbound"], "direct");
    }

    #[test]
    fn reject_unknown_rules() {
        let p = profile(json!({"default_outbound":"proxy","rules":[
            {"type":"custom","action":"route","outbound":"direct","rule_set":["geoip-ru"]}
        ]}));
        assert_eq!(convert(&p, "vpn", "direct"), Err(ConvertError::UnsupportedRule(0)));
    }

    #[test]
    fn reject_dns_hijack_until_implemented() {
        let p = profile(json!({"default_outbound":"proxy","rules":[
            {"type":"custom","action":"hijack-dns","protocol":"dns"}
        ]}));
        assert_eq!(convert(&p, "vpn", "direct"), Err(ConvertError::UnsupportedRule(0)));
    }
}
