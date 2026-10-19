# Routing converter (initial implementation)

The Rust workspace contains one active crate: `throne-routing`.

Supported: `throne://route/` base64url JSON; v1 route profiles; ordered custom route rules matching `domain`, `domain_suffix`, `domain_keyword`, `ip_cidr`, or `ip_is_private=true`. Outbound aliases: `proxy` and `direct`.

The converter returns a **route fragment**, not a complete runnable sing-box configuration. The caller provides existing outbound tags.

**Fail closed:** unknown fields, unsupported actions, rule sets, DNS hijack and other features are rejected. In particular the upstream Bypass Russia profile is not yet convertible: its rule-set and DNS-hijack semantics must be implemented explicitly before enabling it.

Next: validate against a pinned sing-box schema/version, add rule-set support and DNS migration, and run on-device integration tests. Never activate generated config without `sing-box check` and rollback.
