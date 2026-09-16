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
import json
import os
import secrets
import socket
import sys
import time
import urllib.error
import urllib.request
from getpass import getpass
from urllib.parse import unquote
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Third-party — `pip install cryptography` if this isn't already available.
from cryptography.fernet import Fernet, InvalidToken

HASH_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.archive_auth_hash')
ENC_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.archive_enc_key')
ARCHIVE_DIR = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'private-rfi-archive'))
# Enforced here, at every server start, rather than left to whatever the
# directory happened to be created with (umask-dependent, and easy to
# lose track of) — this is what actually backs the privacy policy's
# "chmod 700" claim, instead of that being true by accident.
if os.path.isdir(ARCHIVE_DIR):
    os.chmod(ARCHIVE_DIR, 0o700)
LOGIN_PATH = '/archive-login'
MKDIR_PATH = '/archive-mkdir'
UPLOAD_PATH = '/archive-upload'
GENERATE_PATH = '/archive-generate'
DELETE_PATH = '/archive-delete'
SESSION_COOKIE_NAME = 'archive_session'

# Hybrid generation, "free tier" half: set this once when starting the
# server (`ANTHROPIC_API_KEY=sk-... python3 serve_no_cache.py`) and
# anyone using THIS running instance gets real draft generation with no
# setup of their own — you're the one whose account is billed. Leave it
# unset and /archive-generate just tells the page so, which falls back to
# a visitor's own key entered in the browser (the only option at all on
# the deployed Pages site, since there's no server there to hold a key).
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '').strip()
ANTHROPIC_MODEL = os.environ.get('ANTHROPIC_MODEL', 'claude-sonnet-5').strip()
MAX_GENERATE_BODY = 200 * 1024
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_DELETE_BODY = 4096


def is_valid_segment_name(name):
    # A single, plain path segment — no separators, no ".."/"." tricks,
    # no leading dot (those are reserved for our own scaffolding, e.g.
    # .gitkeep). This alone makes traversal outside ARCHIVE_DIR
    # impossible for anything built from it; no need to double-check via
    # realpath since the input can't contain a path separator at all.
    return (
        bool(name)
        and '/' not in name
        and '\\' not in name
        and name not in ('.', '..')
        and not name.startswith('.')
        and len(name) <= 200
    )


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


def load_or_create_encryption_key():
    # Deliberately NOT derived from the login password: this key has to be
    # available to the process at startup with zero interaction, since the
    # LaunchAgent restarts this server automatically after a crash with no
    # terminal attached to type a password into. Tying it to the login
    # password would mean either prompting on every automatic restart
    # (breaking that) or keeping the plaintext password itself somewhere
    # on disk — a new, worse exposure than anything here today. A
    # separate random key in its own chmod-600 file matches how
    # .archive_auth_hash and the session secret are already handled.
    if os.path.exists(ENC_KEY_FILE):
        with open(ENC_KEY_FILE, 'rb') as f:
            return f.read()
    key = Fernet.generate_key()
    with open(ENC_KEY_FILE, 'wb') as f:
        f.write(key)
    os.chmod(ENC_KEY_FILE, 0o600)
    return key


ENCRYPTION_KEY = load_or_create_encryption_key()
FERNET = Fernet(ENCRYPTION_KEY)

# Login attempt lockout — this server is single-threaded (see `timeout`
# on the handler below), so a plain module-level dict is safe with no
# locking needed. Resets on server restart, same as the session secret;
# that's fine, this is a secondary line of defense against brute-forcing
# the password over the loopback interface, not the only one.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 60
_login_state = {'failures': 0, 'locked_until': 0.0}


def parse_cookies(header_value):
    cookies = {}
    for part in header_value.split(';'):
        if '=' in part:
            k, _, v = part.strip().partition('=')
            cookies[k] = v
    return cookies


class NoCacheAuthHandler(SimpleHTTPRequestHandler):
    # StreamRequestHandler (a parent class) applies this to the connection
    # socket automatically in setup() — without it, a client that claims a
    # Content-Length but never sends that much data leaves self.rfile.read()
    # blocking forever. Since this is a plain HTTPServer with no
    # ThreadingMixIn, that blocks the ENTIRE server, not just one client —
    # confirmed by hanging it with a single malformed request. This bounds
    # every blocking read on the connection, not just the one call site
    # below that first surfaced the problem.
    timeout = 10

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
        # for the containment check because os.path.normcase is a no-op
        # on POSIX, even though the actual filesystem here resolves
        # case-insensitively.
        try:
            target = os.path.realpath(self.translate_path(self.path))
            archive = ARCHIVE_DIR
            if os.path.commonpath([target.lower(), archive.lower()]) != archive.lower():
                return False  # not under the archive at all
            # The file tree itself (names, at any depth) is public — only
            # opening an actual file's content requires login. A folder
            # listing has no content of its own to protect; os.path.isdir
            # is checked on the real (not lowercased) resolved path so
            # this stays correct if this ever runs on a case-sensitive
            # filesystem too.
            return not os.path.isdir(target)
        except Exception:
            # Fail closed: if this request's path can't be cleanly
            # resolved for some unexpected reason, require auth rather
            # than letting an unhandled exception skip the check.
            return True

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
        # HEAD responses report Content-Length as if a GET had happened,
        # but must not actually include a body.
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _archive_file_target(self, path):
        # Returns the real on-disk path if this request targets an actual
        # FILE under the archive (not a directory listing, not anything
        # outside it) — the only case that might need decrypting.
        try:
            target = os.path.realpath(self.translate_path(path))
            if os.path.commonpath([target, ARCHIVE_DIR]) != ARCHIVE_DIR:
                return None
            return target if os.path.isfile(target) else None
        except Exception:
            return None

    def _serve_archive_file(self, target):
        try:
            with open(target, 'rb') as f:
                raw = f.read()
        except OSError:
            return self.send_error(404, 'File not found')
        try:
            body = FERNET.decrypt(raw)
        except InvalidToken:
            # Not a Fernet token — a file already in the archive from
            # before encryption existed. Served as-is rather than
            # failing, so nothing already there becomes unreadable.
            body = raw
        self.send_response(200)
        self.send_header('Content-Type', self.guess_type(target))
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def do_GET(self):
        if self._needs_auth() and not self._authorized():
            return self._deny()
        target = self._archive_file_target(self.path)
        if target:
            return self._serve_archive_file(target)
        return super().do_GET()

    def do_HEAD(self):
        if self._needs_auth() and not self._authorized():
            return self._deny()
        target = self._archive_file_target(self.path)
        if target:
            return self._serve_archive_file(target)
        return super().do_HEAD()

    def _read_bounded_bytes(self, max_len):
        # Shared by every POST endpoint here: validate Content-Length
        # before trusting it (a negative or absurd value fed straight to
        # rfile.read() previously hung the whole single-threaded server —
        # see the `timeout` attribute above for the general backstop, and
        # this bound for the immediate, specific case), and don't let a
        # client that stalls mid-body past the connection timeout escape
        # as an uncaught exception. Returns the raw bytes, or None if
        # invalid — having already sent an error response itself.
        try:
            length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            length = -1
        if length < 0 or length > max_len:
            self.send_error(400, 'Bad Content-Length')
            return None
        try:
            return self.rfile.read(length)
        except socket.timeout:
            self.send_error(408, 'Request body timed out')
            return None

    def _read_bounded_body(self, max_len=4096):
        # Text variant for small form-ish fields (passwords, folder
        # names) — NOT for file uploads, which need the exact bytes
        # (decoding as UTF-8 would corrupt binary content like PDFs).
        raw = self._read_bounded_bytes(max_len)
        if raw is None:
            return None
        return raw.decode('utf-8', errors='replace')

    def _respond(self, status, body_text):
        body = body_text.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == LOGIN_PATH:
            return self._handle_login()
        if self.path == MKDIR_PATH:
            return self._handle_mkdir()
        if self.path == UPLOAD_PATH:
            return self._handle_upload()
        if self.path == GENERATE_PATH:
            return self._handle_generate()
        if self.path == DELETE_PATH:
            return self._handle_delete()
        self.send_error(501, 'Unsupported method (POST)')

    def _handle_generate(self):
        # No login required: this doesn't read archive file content on
        # its own (the page includes any archive excerpts it already
        # fetched, itself auth-gated separately) — it's just a proxy to
        # Anthropic using a key that lives only in this process's
        # environment, never in a file this repo tracks.
        if not ANTHROPIC_API_KEY:
            return self._respond(501, 'No ANTHROPIC_API_KEY set for this server. Add your own key in the browser instead.')
        body = self._read_bounded_bytes(MAX_GENERATE_BODY)
        if body is None:
            return
        try:
            payload = json.loads(body.decode('utf-8'))
            prompt = payload.get('prompt', '')
        except (ValueError, UnicodeDecodeError):
            return self._respond(400, 'Invalid JSON body.')
        if not isinstance(prompt, str) or not prompt.strip():
            return self._respond(400, 'Missing "prompt".')

        upstream_body = json.dumps({
            'model': ANTHROPIC_MODEL,
            'max_tokens': 1536,
            'messages': [{'role': 'user', 'content': prompt}],
        }).encode('utf-8')
        req = urllib.request.Request(
            'https://api.anthropic.com/v1/messages',
            data=upstream_body,
            method='POST',
            headers={
                'x-api-key': ANTHROPIC_API_KEY,
                'anthropic-version': '2023-06-01',
                'content-type': 'application/json',
            },
        )
        try:
            # Real generation can take a while; this is a separate outbound
            # connection to Anthropic, not the client socket, so it doesn't
            # interact with this handler's own `timeout` (that one bounds
            # reads/writes on the browser's connection, not this one).
            with urllib.request.urlopen(req, timeout=90) as resp:
                resp_body = resp.read()
                status = resp.status
        except urllib.error.HTTPError as e:
            resp_body = e.read()
            status = e.code
        except Exception as e:
            return self._respond(502, 'Could not reach Anthropic API: {}'.format(e))
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def _handle_login(self):
        now = time.time()
        if now < _login_state['locked_until']:
            wait = int(_login_state['locked_until'] - now) + 1
            return self._respond(429, 'Too many wrong attempts. Try again in {}s.'.format(wait))

        # A password is never going to be anywhere near 4096 bytes; this
        # is about rejecting a malformed/huge claimed length, not real
        # passwords.
        supplied_pw = self._read_bounded_body()
        if supplied_pw is None:
            return
        if hmac.compare_digest(sha256_hex(supplied_pw), PASSWORD_HASH):
            _login_state['failures'] = 0
            self.send_response(200)
            # Session-only cookie (no Max-Age/Expires): cleared when the
            # browser closes. HttpOnly so page JS can't read the token
            # even via an XSS bug. Path=/ keeps this simple for a server
            # that only ever serves this one small app.
            self.send_header('Set-Cookie', '{}={}; HttpOnly; Path=/; SameSite=Strict'.format(SESSION_COOKIE_NAME, SESSION_SECRET))
            body = b'OK'
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            _login_state['failures'] += 1
            if _login_state['failures'] >= LOGIN_MAX_ATTEMPTS:
                _login_state['locked_until'] = now + LOGIN_LOCKOUT_SECONDS
                _login_state['failures'] = 0
            self._respond(403, 'Wrong password.')

    def _handle_mkdir(self):
        # No login required: creating an empty folder doesn't read or
        # expose any file content, so it doesn't need the same gate as
        # opening a file or looking inside one that already has files in
        # it — same reasoning as why names (but not contents) are public.
        name = self._read_bounded_body()
        if name is None:
            return
        name = name.strip()
        if not is_valid_segment_name(name):
            return self._respond(400, 'Invalid folder name.')
        target = os.path.join(ARCHIVE_DIR, name)
        try:
            os.makedirs(target, exist_ok=False)
            os.chmod(target, 0o700)  # not just relying on umask
        except FileExistsError:
            self._respond(409, 'A folder with that name already exists.')
        except (OSError, ValueError):
            self._respond(500, 'Could not create that folder.')
        else:
            self._respond(200, 'OK')

    def _handle_upload(self):
        # No login required, same reasoning as mkdir: adding a new file
        # doesn't read or expose any EXISTING content in the archive —
        # only opening a file that's already there does. The filename
        # and (optional) target folder ride in headers rather than a
        # multipart body, since this only ever needs to carry one file
        # and one destination — no multipart parser needed for that.
        # Client encodeURIComponent's these before sending — HTTP header
        # values are ASCII-ish, so a filename/folder name with accents,
        # an em-dash, non-Latin characters, etc. wouldn't survive raw.
        file_name = unquote(self.headers.get('X-File-Name', ''))
        folder_name = unquote(self.headers.get('X-Target-Folder', ''))
        if not is_valid_segment_name(file_name):
            return self._respond(400, 'Invalid file name.')
        if folder_name and not is_valid_segment_name(folder_name):
            return self._respond(400, 'Invalid target folder.')

        target_dir = os.path.join(ARCHIVE_DIR, folder_name) if folder_name else ARCHIVE_DIR
        if folder_name and not os.path.isdir(target_dir):
            return self._respond(400, "That folder doesn't exist.")

        data = self._read_bounded_bytes(MAX_UPLOAD_BYTES)
        if data is None:
            return

        target_path = os.path.join(target_dir, file_name)
        try:
            with open(target_path, 'xb') as f:  # 'x' = fail if it already exists
                f.write(FERNET.encrypt(data))
        except FileExistsError:
            self._respond(409, 'A file with that name already exists there.')
        except (OSError, ValueError):
            self._respond(500, 'Could not save that file.')
        else:
            self._respond(200, 'OK')

    def _handle_delete(self):
        # Unlike mkdir/upload, this destroys real content with no undo —
        # requires login, same bar as opening a file's content at all.
        if not self._authorized():
            return self._deny()
        body = self._read_bounded_body(MAX_DELETE_BODY)
        if body is None:
            return
        try:
            payload = json.loads(body)
            rel_path = payload.get('path', '')
        except (ValueError, AttributeError):
            return self._respond(400, 'Invalid JSON body.')
        if not isinstance(rel_path, str) or not rel_path:
            return self._respond(400, 'Missing "path".')

        # Every path segment is validated individually — same guarantee
        # is_valid_segment_name gives mkdir/upload: no segment can contain
        # a separator or "..", so the joined path can't escape ARCHIVE_DIR
        # no matter how many segments deep it goes.
        segments = rel_path.split('/')
        if not segments or not all(is_valid_segment_name(s) for s in segments):
            return self._respond(400, 'Invalid path.')

        target = os.path.join(ARCHIVE_DIR, *segments)
        if not os.path.isfile(target):
            return self._respond(404, 'File not found.')
        try:
            os.remove(target)
        except OSError:
            return self._respond(500, 'Could not remove that file.')
        self._respond(200, 'OK')


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8740
    HTTPServer(('127.0.0.1', port), NoCacheAuthHandler).serve_forever()
