# SPDX-License-Identifier: Apache-2.0
"""Small, bounded HTTP client. Never puts credentials into logs or command lines."""
import json
import os
import urllib.error
import urllib.parse
import urllib.request


def secret(name, default=""):
    """Value of environment variable ``name``, or the content of the file named by ``name_FILE`` (Docker/Kubernetes secrets)."""
    path = os.getenv(name + "_FILE")
    if path:
        with open(path, encoding="utf-8") as stream:
            return stream.read().strip()
    return os.getenv(name, default)


def check_url(url, allow_http=False):
    """Validate a base URL (hostname, no credentials or fragment, HTTPS unless ``allow_http``) and strip trailing slashes."""
    parsed = urllib.parse.urlsplit(url)
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("URL must have a hostname and no credentials or fragment")
    if parsed.scheme != "https" and not (allow_http and parsed.scheme == "http"):
        raise ValueError("HTTPS is required; HTTP must be explicitly enabled for internal traffic")
    return url.rstrip("/")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuses redirects so that credential headers are never sent to another origin."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Do not forward Authorization / X-Api-Key to another origin.
        return None


def request(url, data=None, headers=None, method=None):
    """Send one request and return ``(decoded body, response headers)``; JSON bodies are decoded, empty ones are ``None``. Responses above 16 MiB are rejected."""
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    with urllib.request.build_opener(NoRedirect).open(req, timeout=30) as response:
        raw = response.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("HTTP response exceeds limit")
        if not raw:
            result = None
        else:
            try:
                result = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                result = raw.decode("utf-8", errors="replace")
        return result, response.headers


def post_json(url, payload, headers=None):
    """POST ``payload`` as JSON and return the decoded response body."""
    return request(url, json.dumps(payload).encode(),
                   {"Content-Type": "application/json", **(headers or {})}, "POST")[0]
