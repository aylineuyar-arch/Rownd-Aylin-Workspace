#!/usr/bin/env python3
"""Local dev server for this folder — no caching, loopback-only, and real
session-cookie auth in front of the private RFI/RFP archive.

Three separate problems this fixes vs. plain `python -m http.server`:

1. Caching: browsers cached index.html, so edits didn't always show up on
   reload. Every response here gets Cache-Control: no-store.

2. Network exposure: `python -m http.server` binds to all network
   interfaces by default (0.0.0.0), so anyone else on the same WiFi/LAN
   could browse straight to your files, with no login of any kind. This
   binds to 127.0.0.1 only — nothing outside this machine can reach it.

3. Real auth, enforced by the server, not the page's JavaScript: a
   password checked in the page's own JS protects nothing, since a direct
   request (curl, another tab, another device before fix #2) never goes
   through that JS at all. This originally used HTTP Basic Auth (a 401 +
   WWW-Authenticate challenge), which is real server-side enforcement —
   but in practice it turned out to be unreliable: some browser/extension
   combinations retry a 401-with-WWW-Authenticate response in a tight
   loop trying to negotiate the browser's native credential dialog,
   hammering this server dozens of times for a single page load and
   sometimes failing outright. Switched to a session cookie instead:
   POST the password once to /archive-login, get back an HttpOnly cookie,
   and every request after that (including a plain link click to open a
   file, not just this page's own fetch calls) carries it automatically —
   no native browser dialog ever enters the picture, so there's nothing
   for that negotiation loop to trigger on.

The chosen password is never written into any file this repo tracks:
it's hashed (SHA-256) and cached in Rownd/.archive_auth_hash, which is
git-ignored the same way the archive folder is. Set ARCHIVE_PASSWORD in
the environment to skip the interactive prompt (handy for scripted runs);
otherwise you're prompted once and it's remembered (as a hash) for next
time. The session cookie's own secret is different — generated fresh
every time this server starts and never written to disk at all, so
restarting the server always requires logging in again.
"""
import hashlib
import hmac
import os
import secrets
import sys
from getpass import getpass
from http.server import HTTPServer, SimpleHTTPRequestHandler

HASH_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.archive_auth_hash')
ARCHIVE_DIR = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'private-rfi-archive'))
LOGIN_PATH = '/archive-login'
SESSION_COOKIE_NAME = 'archive_session'


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
# Fresh every run, never persisted — restarting the server always requires
# logging in again, which keeps a stale cookie from outliving the process.
SESSION_SECRET = secrets.token_hex(32)


def parse_cookies(header_value):
    cookies = {}
    for part in header_value.split(';'):
        if '=' in part:
            k, _, v = part.strip().partition('=')
            cookies[k] = v
    return cookies


class NoCacheAuthHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

    def _needs_auth(self):
        # Resolve the request the SAME way the base class will actually
        # resolve it (translate_path already URL-decodes and collapses
        # ., .., and repeated slashes) before deciding whether it targets
        # the archive — comparing against the raw request string instead
        # previously let a case-varied path and a URL-encoded slash both
        # slip past auth while still serving the real file. Lowercased
        # because os.path.normcase is a no-op on POSIX, even though the
        # actual filesystem here resolves case-insensitively.
        target = os.path.realpath(self.translate_path(self.path)).lower()
        archive = ARCHIVE_DIR.lower()
        try:
            common = os.path.commonpath([target, archive])
        except ValueError:
            return False
        return common == archive

    def _authorized(self):
        cookies = parse_cookies(self.headers.get('Cookie', ''))
        token = cookies.get(SESSION_COOKIE_NAME, '')
        return bool(token) and hmac.compare_digest(token, SESSION_SECRET)

    def _deny(self):
        # Deliberately a plain 403 with no WWW-Authenticate header — that
        # header is what makes browsers attempt native Basic-Auth
        # negotiation, which is the exact behavior that turned out to be
        # unreliable. A 403 is just a denied request, nothing more.
        body = b'Password required. Go to the New Draft / Reference Documents page and enter it there.'
        self.send_response(403)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self._needs_auth() and not self._authorized():
            return self._deny()
        return super().do_GET()

    def do_HEAD(self):
        if self._needs_auth() and not self._authorized():
            return self._deny()
        return super().do_HEAD()

    def do_POST(self):
        if self.path != LOGIN_PATH:
            self.send_error(501, 'Unsupported method (POST)')
            return
        length = int(self.headers.get('Content-Length', 0))
        supplied_pw = self.rfile.read(length).decode('utf-8', errors='replace')
        if hmac.compare_digest(sha256_hex(supplied_pw), PASSWORD_HASH):
            body = b'OK'
            self.send_response(200)
            # Session-only cookie (no Max-Age/Expires): cleared when the
            # browser closes. HttpOnly so page JS can't read the token
            # even via an XSS bug. Path=/ keeps this simple for a server
            # that only ever serves this one small app.
            self.send_header('Set-Cookie', '{}={}; HttpOnly; Path=/; SameSite=Strict'.format(SESSION_COOKIE_NAME, SESSION_SECRET))
        else:
            body = b'Wrong password.'
            self.send_response(403)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8740
    HTTPServer(('127.0.0.1', port), NoCacheAuthHandler).serve_forever()
