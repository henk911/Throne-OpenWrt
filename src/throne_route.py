#!/usr/bin/env python3
"""Offline Throne route-profile decoder; no network or router changes."""
import base64
import json
import sys
from urllib.parse import urlsplit


def decode_route(uri: str) -> dict:
    parts = urlsplit(uri.strip())
    if parts.scheme != "throne" or parts.netloc != "route" or parts.query or parts.fragment:
        raise ValueError("Expected throne://route/<base64url>")
    token = parts.path.lstrip("/")
    if not token or len(token) > 1_000_000:
        raise ValueError("Invalid payload length")
    payload = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
    profile = json.loads(payload)
    if not isinstance(profile, dict) or not isinstance(profile.get("rules"), list):
        raise ValueError("Profile must contain rules array")
    return profile


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit('Usage: python3 src/throne_route.py "throne://route/..."')
    print(json.dumps(decode_route(sys.argv[1]), ensure_ascii=False, indent=2))
