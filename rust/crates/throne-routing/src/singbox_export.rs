use std::collections::HashMap;
use serde_json::{json, Map, Value};
use crate::throne_import::Profile;

#[derive(Debug, PartialEq, Eq)]
pub enum ConvertError {
    UnsupportedRule(usize),
    UnsupportedAction(usize),
    InvalidRule(usize),
    UnknownOutbound(String),
    UnknownRuleSet(String),
}

/// A route fragment only. Rule-set definitions must be provided and validated separately.
/// No remote URLs are inferred from names such as geosite-ru.
pub fn convert(profile: &Profile, proxy_tag: &str, direct_tag: &str) -> Result<Value, ConvertError> {
    convert_with_rule_sets(profile, proxy_tag, direct_tag, &HashMap::new())
}

pub fn convert_with_rule_sets(
    profile: &Profile,
    proxy_tag: &str,
    direct_tag: &str,
    rule_sets: &HashMap<String, String>,
) -> Result<Value, ConvertError> {
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
        let allowed = ["name", "type", "action", "outbound", "domain", "domain_suffix",
            "domain_keyword", "ip_cidr", "ip_is_private", "rule_set", "protocol"];
        if obj.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(ConvertError::UnsupportedRule(index));
        }
        let mut result = Map::new();
        let mut matches = 0;
        for key in ["domain", "domain_suffix", "domain_keyword", "ip_cidr", "protocol"] {
            if let Some(value) = obj.get(key) {
                let list = if key == "protocol" && value.is_string() {
                    vec![value.clone()]
                } else {
                    value.as_array().ok_or(ConvertError::InvalidRule(index))?.clone()
                };
                if list.is_empty() || !list.iter().all(|v| v.as_str().is_some_and(|s| !s.is_empty())) {
                    return Err(ConvertError::InvalidRule(index));
                }
                result.insert(key.to_string(), Value::Array(list));
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
        if let Some(value) = obj.get("rule_set") {
            let list = value.as_array().ok_or(ConvertError::InvalidRule(index))?;
            if list.is_empty() {
                return Err(ConvertError::InvalidRule(index));
            }
            let mut resolved = Vec::new();
            for name in list {
                let name = name.as_str().filter(|s| !s.is_empty()).ok_or(ConvertError::InvalidRule(index))?;
                let tag = rule_sets.get(name).filter(|s| !s.is_empty())
                    .ok_or_else(|| ConvertError::UnknownRuleSet(name.to_owned()))?;
                resolved.push(json!(tag));
            }
            result.insert("rule_set".into(), Value::Array(resolved));
            matches += 1;
        }
        if matches == 0 {
            return Err(ConvertError::InvalidRule(index));
        }
        match action {
            "route" => {
                let dest = obj.get("outbound").and_then(Value::as_str).ok_or(ConvertError::InvalidRule(index))?;
                result.insert("action".into(), json!("route"));
                result.insert("outbound".into(), json!(outbound(dest)?));
            }
            "hijack-dns" => {
                if obj.contains_key("outbound") || matches != 1 ||
                    result.get("protocol") != Some(&json!(["dns"])) {
                    return Err(ConvertError::InvalidRule(index));
                }
                result.insert("action".into(), json!("hijack-dns"));
            }
            _ => return Err(ConvertError::UnsupportedAction(index)),
        }
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
    }

    #[test]
    fn rejects_missing_rule_set_mapping() {
        let p = profile(json!({"default_outbound":"proxy","rules":[
            {"type":"custom","action":"route","outbound":"direct","rule_set":["geoip-ru"]}
        ]}));
        assert_eq!(convert(&p, "vpn", "direct"), Err(ConvertError::UnknownRuleSet("geoip-ru".into())));
    }

    #[test]
    fn maps_rule_set_to_existing_tag() {
        let p = profile(json!({"default_outbound":"proxy","rules":[
            {"type":"custom","action":"route","outbound":"direct","rule_set":["geoip-ru"]}
        ]}));
        let mappings = HashMap::from([("geoip-ru".into(), "ru-ip".into())]);
        let out = convert_with_rule_sets(&p, "vpn", "direct", &mappings).unwrap();
        assert_eq!(out["route"]["rules"][0]["rule_set"], json!(["ru-ip"]));
    }

    #[test]
    fn converts_dns_hijack_action() {
        let p = profile(json!({"default_outbound":"proxy","rules":[
            {"type":"custom","action":"hijack-dns","protocol":"dns"}
        ]}));
        let out = convert(&p, "vpn", "direct").unwrap();
        assert_eq!(out["route"]["rules"][0]["action"], "hijack-dns");
        assert_eq!(out["route"]["rules"][0]["protocol"], json!(["dns"]));
    }

    #[test]
    fn rejects_unsafe_dns_hijack() {
        let p = profile(json!({"default_outbound":"proxy","rules":[
            {"type":"custom","action":"hijack-dns","protocol":"dns","outbound":"proxy"}
        ]}));
        assert_eq!(convert(&p, "vpn", "direct"), Err(ConvertError::InvalidRule(0)));
    }
}
