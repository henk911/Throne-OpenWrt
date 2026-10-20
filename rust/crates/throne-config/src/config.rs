use serde_json::{json, Value};
use throne_routing::{convert_with_rule_sets, Profile};
use crate::rule_sets::{local_definitions, tag_map, RuleSetSpec};
use std::path::Path;

/// Builds a complete sing-box JSON document from caller-supplied inbound/outbound
/// definitions. Does not infer or generate VPN credentials.
pub fn build_config(
    profile: &Profile,
    inbounds: Vec<Value>,
    outbounds: Vec<Value>,
    specs: &[RuleSetSpec],
    cache_root: &Path,
    proxy_tag: &str,
    direct_tag: &str,
) -> Result<Value, String> {
    if inbounds.is_empty() || outbounds.is_empty() {
        return Err("inbounds and outbounds must not be empty".into());
    }
    for outbound in &outbounds {
        if outbound.get("tag").and_then(Value::as_str).is_none() {
            return Err("every outbound requires a tag".into());
        }
    }
    for tag in [proxy_tag, direct_tag] {
        if !outbounds.iter().any(|o| o["tag"].as_str() == Some(tag)) {
            return Err(format!("missing outbound: {tag}"));
        }
    }
    crate::rule_sets::validate_specs(specs, cache_root)?;
    let mut route = convert_with_rule_sets(profile, proxy_tag, direct_tag, &tag_map(specs))
        .map_err(|e| format!("route conversion failed: {e:?}"))?["route"].clone();
    route["rule_set"] = json!(local_definitions(specs, cache_root));
    Ok(json!({
        "log": {"level": "warn"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route
    }))
}
