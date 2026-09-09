#!/usr/bin/env python3
"""Local dev server for this folder that disables browser caching.

Plain `python -m http.server` lets browsers cache index.html, which made
edited pages look unchanged after a normal reload (confusing "why isn't
this working" moments — the browser was just showing an old copy). This
sends Cache-Control: no-store on every response so every load is fresh.
"""
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler


class NoCacheHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8740
    HTTPServer(('', port), NoCacheHandler).serve_forever()
