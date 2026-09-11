#!/usr/bin/env python3
"""Local dev server for this folder — no caching, loopback-only, and real
HTTP Basic Auth in front of the private RFI/RFP archive.

Two separate problems this fixes vs. plain `python -m http.server`:

1. Caching: browsers cached index.html, so edits didn't always show up on
   reload. Every response here gets Cache-Control: no-store.

2. Actual security for /private-rfi-archive/, not a UI illusion of it:
   - `python -m http.server` binds to all network interfaces by default
     (0.0.0.0), so anyone else on the same WiFi/LAN could browse straight
     to your files, with no login of any kind. This binds to 127.0.0.1
     only — nothing outside this machine can reach it, period.
   - A password checked in the page's own JavaScript protects nothing: a
     direct request (curl, another browser tab, another device before the
     loopback fix above) reads the files with no gate at all, since
     there's no server enforcing anything. So auth lives here, in the
     server process, as real HTTP Basic Auth — a 401 challenge that no
     amount of dev-tools access to the page's JS can bypass, because the
     page's JS is never in the request path.

The password itself is never written into any file this repo tracks: it's
hashed (SHA-256) and cached in Rownd/.archive_auth_hash, which is
git-ignored the same way the archive folder is. Set ARCHIVE_PASSWORD in
the environment to skip the interactive prompt (handy for scripted runs);
otherwise you're prompted once and it's remembered (as a hash) for next
time.
"""
import hashlib
import hmac
import os
import sys
from base64 import b64decode
from getpass import getpass
from http.server import HTTPServer, SimpleHTTPRequestHandler

HASH_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.archive_auth_hash')
PROTECTED_PREFIX = '/private-rfi-archive'


def sha256_hex(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def load_or_set_password_hash():
    env_pw = os.environ.get('ARCHIVE_PASSWORD')
    if env_pw:
        return sha256_hex(env_pw)
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE) as f:
            return f.read().strip()
    print('No archive password set yet for this machine.')
    while True:
        pw = getpass('Set a password to protect the private RFI/RFP archive: ')
        confirm = getpass('Confirm password: ')
        if pw and pw == confirm:
            break
        print("Passwords didn't match (or were empty) — try again.")
    digest = sha256_hex(pw)
    with open(HASH_FILE, 'w') as f:
        f.write(digest)
    os.chmod(HASH_FILE, 0o600)
    print('Password set. Stored (hashed) in .archive_auth_hash — never committed, never pushed.')
    return digest


PASSWORD_HASH = load_or_set_password_hash()


class NoCacheAuthHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

    def _needs_auth(self):
        return self.path == PROTECTED_PREFIX or self.path.startswith(PROTECTED_PREFIX + '/')

    def _authorized(self):
        header = self.headers.get('Authorization', '')
        if not header.startswith('Basic '):
            return False
        try:
            decoded = b64decode(header[len('Basic '):]).decode('utf-8')
            _, _, supplied_pw = decoded.partition(':')
        except Exception:
            return False
        return hmac.compare_digest(sha256_hex(supplied_pw), PASSWORD_HASH)

    def _challenge(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Private RFI/RFP Archive"')
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Password required.')

    def do_GET(self):
        if self._needs_auth() and not self._authorized():
            return self._challenge()
        return super().do_GET()

    def do_HEAD(self):
        if self._needs_auth() and not self._authorized():
            return self._challenge()
        return super().do_HEAD()


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8740
    HTTPServer(('127.0.0.1', port), NoCacheAuthHandler).serve_forever()
