import json
import unittest
from unittest.mock import patch

from app.services.tech_detector import TechDetector


class TechDetectorTests(unittest.TestCase):
    def test_detects_shopify_and_wordpress_signals_from_html_and_headers(self):
        detector = TechDetector()

        response = type(
            "Resp",
            (),
            {
                "text": """
                <html>
                  <head>
                    <meta name="generator" content="WordPress 6.4" />
                  </head>
                  <body>
                    <script src="https://cdn.shopify.com/s/files/1/0001/0002/t/1/assets/app.js"></script>
                    <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />
                  </body>
                </html>
                """,
                "headers": {"server": "nginx/1.25.0", "x-powered-by": "PHP/8.2.3"},
                "cookies": {},
                "history": [],
            },
        )

        with patch("requests.get", return_value=response):
            detected = detector.detect("https://example.test")

        self.assertIn("WordPress", detected)
        self.assertIn("Shopify", detected)
        self.assertIn("PHP", detected)
        self.assertIn("Nginx", detected)

    def test_detects_tomcat_java_and_goober_from_headers_cookies_and_html(self):
        detector = TechDetector()

        response = type(
            "Resp",
            (),
            {
                "text": """
                <html>
                  <head><title>Altoro Mutual</title></head>
                  <body>
                    <script src="/js/goober.js"></script>
                  </body>
                </html>
                """,
                "headers": {
                    "server": "Apache-Coyote/1.1",
                    "x-powered-by": "Servlet/3.0",
                },
                "cookies": {"jsessionid": "ABC123XYZ"},
                "history": [],
            },
        )

        with patch("requests.get", return_value=response):
            detected = detector.detect("https://demo.testfire.net")

        self.assertIn("Apache Tomcat", detected)
        self.assertIn("Java", detected)
        self.assertIn("Goober", detected)

    def test_whatweb_json_is_parsed_dynamically(self):
        detector = TechDetector()
        raw_json = json.dumps([
            {
                "target": "https://demo.testfire.net",
                "plugins": {
                    "HTTPServer": {"string": ["Apache-Coyote/1.1"]},
                    "X-Powered-By": {"string": ["Servlet/3.0"]},
                    "Java": {"version": ["1.8.0_211"]},
                    "Goober": {"version": []}
                }
            }
        ])

        parsed = detector._parse_whatweb_json(raw_json)

        self.assertIn("Apache Tomcat", parsed)
        self.assertIn("Java Servlet", parsed)
        self.assertIn("Java", parsed)
        self.assertIn("Goober", parsed)


if __name__ == "__main__":
    unittest.main()

