import base64
import json
import unittest
from src.throne_route import decode_route


class RouteTests(unittest.TestCase):
    def test_valid_route(self):
        profile = {"name": "Bypass Russia", "rules": [], "default_outbound": "proxy"}
        token = base64.urlsafe_b64encode(json.dumps(profile).encode()).decode().rstrip("=")
        self.assertEqual(decode_route("throne://route/" + token), profile)

    def test_invalid_scheme(self):
        with self.assertRaises(ValueError):
            decode_route("https://example.com")

    def test_missing_rules(self):
        token = base64.urlsafe_b64encode(b'{"name":"invalid"}').decode().rstrip("=")
        with self.assertRaises(ValueError):
            decode_route("throne://route/" + token)


if __name__ == "__main__":
    unittest.main()
