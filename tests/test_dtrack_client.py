# SPDX-License-Identifier: Apache-2.0
import io
import unittest
import urllib.error
from unittest.mock import patch

from patchwatch.dtrack.client import DependencyTrack


def http_error(code):
    return urllib.error.HTTPError("https://dtrack.example", code, "x", {}, io.BytesIO(b""))


class NotModified(unittest.TestCase):
    def setUp(self):
        self.client = DependencyTrack("https://dtrack.example", {})

    def test_unchanged_update_is_not_an_error_in_v1_and_v2(self):
        with patch("patchwatch.dtrack.client.request", side_effect=http_error(304)):
            self.assertIsNone(self.client.call("project/x", {"active": True}, "PATCH"))
            self.assertIsNone(self.client.v2("secrets/x", {"value": "v"}, "PATCH"))

    def test_other_errors_still_raise(self):
        with patch("patchwatch.dtrack.client.request", side_effect=http_error(409)):
            with self.assertRaises(urllib.error.HTTPError):
                self.client.call("project/x", {}, "PATCH")


if __name__ == "__main__":
    unittest.main()
