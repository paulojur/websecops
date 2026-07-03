import unittest

from app.services.remediation_engine import RemediationEngine


class RemediationEngineTests(unittest.TestCase):
    def test_clickjacking_alert_gets_header_remediation(self):
        engine = RemediationEngine()

        remediations = engine.for_alert({
            "alert": "Missing Anti-clickjacking Header",
            "description": "X-Frame-Options header is not present.",
            "url": "https://example.test",
            "risk": "Medium",
        })

        self.assertEqual(1, len(remediations))
        self.assertEqual("Protecao contra clickjacking", remediations[0]["title"])
        self.assertIn("frame-ancestors", remediations[0]["snippets"]["nginx"])

    def test_cookie_alert_gets_cookie_hardening(self):
        engine = RemediationEngine()

        remediations = engine.for_alert({
            "alert": "Cookie No HttpOnly Flag",
            "description": "A cookie was set without HttpOnly.",
            "url": "https://example.test",
            "risk": "Medium",
        })

        self.assertEqual(1, len(remediations))
        self.assertEqual("Endurecer atributos de cookies", remediations[0]["title"])
        self.assertIn("SameSite", remediations[0]["recommendation"])

    def test_baseline_prefers_detected_server(self):
        engine = RemediationEngine()

        baseline = engine.baseline({"Nginx": {"version": "1.25", "category": "Web Server"}})

        self.assertEqual("nginx", baseline[0]["preferred_server"])
        self.assertIn("Strict-Transport-Security", baseline[0]["snippets"]["nginx"])


if __name__ == "__main__":
    unittest.main()
