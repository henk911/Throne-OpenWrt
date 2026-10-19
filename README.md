# Throne Lite for OpenWrt

Lightweight Throne-inspired routing manager for OpenWrt.

**Status:** early prototype; NOT installable on a router yet.

Target: Cudy WR3000U v1, OpenWrt 25.12.x, ARM64.

## Implemented
- Offline decoder and validation of `throne://route/` base64url JSON profiles.
- Python standard-library unit tests.

## Roadmap
1. Validate route semantics and convert supported rules to sing-box.
2. Safe configuration management and rollback.
3. OpenWrt procd/ubus/UCI integration.
4. LuCI interface and subscription handling.
5. Optional WARP/AWG and component management.

## Run tests

```sh
python3 -m unittest discover -s tests -v
```

## Security
Never execute imported profile content. Imported routing profiles are untrusted. Validate configs before activation and retain last known-good configuration. No firewall changes are performed by this prototype.

## Licensing
No Throne upstream source code is included at this stage. Audit upstream licenses before reuse.
