"""Objective executable test. Written BEFORE the model authored the source."""
import unittest
from duration import parse_duration


class ParseDurationTests(unittest.TestCase):
    def test_accepts_each_unit(self):
        for text, expected in [("0s", 0), ("90s", 90), ("5m", 300),
                               ("2h", 7200), ("1d", 86400), ("120m", 7200),
                               ("1s", 1), ("24h", 86400), ("7d", 604800)]:
            with self.subTest(text=text):
                self.assertEqual(parse_duration(text), expected)

    def test_returns_int(self):
        self.assertIsInstance(parse_duration("5m"), int)

    def test_rejects_malformed(self):
        for text in ["", "90", "90x", "90S", " 90s", "90s ", "9 0s", "-5m",
                     "+5m", "1.5h", "s", "1m30s", "m5", "90ss", "0x10s"]:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    parse_duration(text)

    def test_rejects_non_str_as_valueerror(self):
        for value in [None, 90, 5.0, ["90s"], {"d": 1}]:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_duration(value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
