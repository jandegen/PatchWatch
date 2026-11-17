# SPDX-License-Identifier: Apache-2.0
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest
import urllib.error
from patchwatch.core.http import post_json, request


class HTTPTests(unittest.TestCase):
    def test_plain_webhook_acknowledgement_and_no_redirect(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                self.rfile.read(int(self.headers.get('Content-Length', 0)))
                if self.path == '/redirect':
                    self.send_response(302); self.send_header('Location', '/ok'); self.end_headers()
                else:
                    self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        url = 'http://127.0.0.1:' + str(server.server_port)
        self.assertEqual(post_json(url + '/ok', {'text': 'hello'}), 'ok')
        with self.assertRaises(urllib.error.HTTPError) as error:
            request(url + '/redirect', b'{}', {'X-Api-Key': 'must-not-redirect'})
        self.assertEqual(error.exception.code, 302)
        error.exception.close()
