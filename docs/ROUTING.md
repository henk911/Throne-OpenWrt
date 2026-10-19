# Throne Lite routing converter

Rust crate: `throne-routing`. This crate is an offline parser and route-fragment generator, not an OpenWrt daemon.

## Supported in stage 3
- Throne `throne://route/` base64url JSON profiles (v1).
- Ordered custom rules with domain, domain_suffix, domain_keyword, ip_cidr and ip_is_private=true.
- `rule_set` references only with explicit mappings to **existing** sing-box rule-set tags.
- `hijack-dns` action with exactly `protocol: dns`.
- Outbound aliases `proxy` and `direct` mapped to caller-supplied tags.

## Explicit limitations
- No GeoSite/GeoIP database downloads, rule-set definition generation, or remote URL trust model yet.
- A real Bypass Russia profile needs mappings and separately configured, valid rule-set definitions.
- No complete sing-box config is generated, and no router settings are changed.
- No automatic assumption that an upstream geosite list has a corresponding valid SRS file.
- Unsupported keys/actions and missing mappings cause errors, never silent fallback.
- Rule ordering is preserved.

## Before production
Validate the fragment inside a complete configuration with the **pinned** target sing-box version, run `sing-box check`, verify DNS routing and rule-set semantics, then implement atomic apply/rollback and on-device tests.
