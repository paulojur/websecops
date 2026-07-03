import subprocess
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
                    <meta name=\"generator\" content=\"WordPress 6.4\" />
                  </head>
                  <body>
                    <script src=\"https://cdn.shopify.com/s/files/1/0001/0002/t/1/assets/app.js\"></script>
                    <link rel=\"stylesheet\" href=\"/wp-content/themes/twentytwentyfour/style.css\" />
                  </body>
                </html>
                """,
                "headers": {"server": "nginx/1.25.0", "x-powered-by": "PHP/8.2.3"},
            },
        )

        with patch("requests.get", return_value=response):
            detected = detector.detect("https://example.test")

        self.assertIn("WordPress", detected)
        self.assertIn("Shopify", detected)
        self.assertIn("PHP", detected)
        self.assertIn("Nginx", detected)

    def test_whatweb_output_is_parsed_into_technologies(self):
        detector = TechDetector()
        output = "[200] https://example.test\nHTTPServer: nginx/1.25.0\nX-Powered-By: PHP/8.2.3\nWordPress 6.4"

        parsed = detector._parse_whatweb_output(output)

        self.assertIn("WordPress", parsed)
        self.assertIn("Nginx", parsed)
        self.assertIn("PHP", parsed)


if __name__ == "__main__":
    unittest.main()
