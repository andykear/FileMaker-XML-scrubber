#!/usr/bin/env python3
# ============================================================
#  FileMaker XML Scrubber — engine + UI
#  Engine functions below are unit-tested under jsdom.
#  Findings are DERIVED from what is actually redacted, so the
#  on-screen count and the downloaded file can never disagree.
# ============================================================

import argparse
import base64
import functools
import glob
import os
import re
import shlex
import sys
from xml.dom import expatbuilder, minidom
from xml.parsers.expat import ExpatError

# ── JS COMPAT ────────────────────────────────────────────────
_JS_WS_CLASS = '\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff'
_JS_WS_CHARS = '\t\n\v\f\r \u00a0\u1680' + ''.join(chr(c) for c in range(0x2000, 0x200b)) + '\u2028\u2029\u202f\u205f\u3000\ufeff'
_JS_DOT = '[^\n\r\u2028\u2029]'


@functools.lru_cache(maxsize=None)
def jsre(src, flags=0):
    out = []
    i, n, in_cls = 0, len(src), False
    while i < n:
        c = src[i]
        if c == '\\' and i + 1 < n:
            d = src[i + 1]
            if d == 's':
                out.append(_JS_WS_CLASS if in_cls else '[' + _JS_WS_CLASS + ']')
            elif d == 'S':
                if in_cls:
                    raise ValueError('\\S inside a character class: ' + src)
                out.append('[^' + _JS_WS_CLASS + ']')
            else:
                out.append(c + d)
            i += 2
            continue
        if in_cls:
            if c == ']':
                in_cls = False
                out.append(c)
            elif c in '[&~|':
                out.append('\\' + c)
            else:
                out.append(c)
        elif c == '[':
            in_cls = True
            out.append(c)
            if src[i + 1:i + 2] == '^':
                out.append('^')
                i += 1
        elif c == '.':
            out.append(_JS_DOT)
        elif c == '$':
            out.append(r'\Z')
        else:
            out.append(c)
        i += 1
    return re.compile(''.join(out), flags | re.ASCII)


def js_trim(s):
    return s.strip(_JS_WS_CHARS)


_WS_RUN = jsre(r'\s+')

# ── ENGINE ───────────────────────────────────────────────────
_ESCAPE_RE = jsre(r'[.*+?^${}()|[\]\\]')


def escape_re(s):
    return _ESCAPE_RE.sub(lambda m: '\\' + m.group(0), str(s))


def build_known_key_re(o):
    p = []
    if o['sk']:     p += [r'sk-proj-[\w-]{10,}', r'sk-[\w-]{20,}']       # OpenAI (also catches sk-ant- Anthropic)
    if o['aiza']:   p += [r'AIza[\w-]{30,}']                             # Google
    if o['xai']:    p += [r'xai-[\w-]{10,}']                             # xAI
    if o['groq']:   p += [r'gsk_[A-Za-z0-9]{20,}']                       # Groq
    if o['aws']:    p += [r'AKIA[0-9A-Z]{16}', r'ASIA[0-9A-Z]{16}']      # AWS access key id
    if o['github']: p += [r'gh[posru]_[A-Za-z0-9]{20,}', r'github_pat_[A-Za-z0-9_]{20,}']
    if o['slack']:  p += [r'xox[baprs]-[A-Za-z0-9-]{10,}']
    if o['stripe']: p += [r'[sr]k_(?:live|test)_[A-Za-z0-9]{20,}']       # Stripe live + test secret/restricted keys
    if o['sendgrid']: p += [r'SG\.[\w-]{16,}\.[\w-]{16,}']               # SendGrid API key (SG.xxxx.xxxx)
    if o['otto']:   p += [r'dk_[A-Za-z0-9]{8,}', r'ak_[A-Za-z0-9]{8,}']  # OttoFMS Data API (dk_) and Admin API (ak_) keys
    if o['pem']:    p += [r'-----BEGIN[A-Z0-9 ]*PRIVATE KEY-----']       # PEM private key block (RSA/EC/OPENSSH/PKCS8)
    if o['jwt']:    p += [r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}']  # JWT/JWS: three base64url segments, header always starts eyJ ({" encoded)
    if o['webhook']:                                                     # incoming-webhook URLs carry their own auth token
        p.append(r'hooks\.slack\.com/services/[A-Za-z0-9/]+')           # Slack
        p.append(r'discord(?:app)?\.com/api/webhooks/\d+/[\w-]+')       # Discord
        p.append(r'[A-Za-z0-9.-]+\.webhook\.office\.com/')              # Microsoft Teams / Power Automate
    return jsre('|'.join(p)) if p else None


def kw_parts_from(a):
    p = []
    if a['apikey']:     p += ['api[_-]?key', 'apikey']
    if a['token']:      p += ['token', 'bearer', 'authorization']
    if a['password']:   p += ['password', 'passwd']
    if a['secret']:     p += ['secret']
    if a['smtp']:       p += ['smtp[_-]?pass', 'smtp[_-]?key']
    if a['privatekey']: p += ['private[_-]?key', 'auth[_-]?key', 'ssh[_-]?key', 'sftp[_-]?pass', 'passphrase']
    if a['credential']: p += ['credential', 'oauth']
    for c in a.get('custom') or []:
        p.append(escape_re(c))
    return p


def categ_from_name(name):
    n = (name or '').lower()
    if re.search(r'api[_-]?key|apikey', n): return 'api_key'
    if re.search(r'token|bearer|authorization', n): return 'token'
    if re.search(r'password|passwd', n):    return 'password'
    if re.search(r'secret', n):             return 'secret'
    if re.search(r'smtp', n):               return 'smtp'
    if re.search(r'oauth', n):              return 'oauth'
    return 'credential'


def excerpt(b):
    s = _WS_RUN.sub(' ', js_trim(b or ''))
    return s[:217] + '\u2026' if len(s) > 220 else s


_MARK_RE = jsre(r'\[REDACTED\]|\[HOST\]|\[USER\]|\[EMAIL\]|\[CARD\]')


# Build a preview from the REDACTED text: short windows around each marker, so
# findings show what was redacted (secret masked), not the start of the calc,
# which is often a documentation comment.
def preview_redactions(text, max_wins=None):
    max_wins = max_wins or 6
    marks = [(m.start(), m.end()) for m in _MARK_RE.finditer(text)]
    if not marks:
        return excerpt(text)
    wins = []
    for i in range(min(len(marks), max_wins)):
        a = max(0, marks[i][0] - 36)
        e = min(len(text), marks[i][1] + 36)
        wins.append(('\u2026' if a > 0 else '') + js_trim(_WS_RUN.sub(' ', text[a:e])) + ('\u2026' if e < len(text) else ''))
    more = '(+' + str(len(marks) - max_wins) + ' more not shown)' if len(marks) > max_wins else ''
    return '\n'.join(wins + ([more] if more else []))


_BARE_DQ = jsre(r'^"([^"\\]|\\.)*"$')
_BARE_SQ = jsre(r"^'([^'\\]|\\.)*'$")


def is_bare_string(t):
    t = js_trim(t or '')
    return bool(_BARE_DQ.search(t) or _BARE_SQ.search(t))


# Splits the inside of a function call's parens into its top-level,
# semicolon-separated arguments, respecting nested parens and string
# literals so a comma or semicolon inside a quoted string or a nested
# call doesn't split where it shouldn't.
def split_top_level_args(span):
    args, depth, cur, in_str, q, esc = [], 0, [], False, '', False
    for c in span:
        if in_str:
            cur.append(c)
            if esc: esc = False
            elif c == '\\': esc = True
            elif c == q: in_str = False
            continue
        if c == '"' or c == "'":
            in_str = True; q = c; cur.append(c); continue
        if c == '(':
            depth += 1; cur.append(c); continue
        if c == ')':
            depth -= 1; cur.append(c); continue
        if c == ';' and depth == 0:
            args.append(''.join(cur)); cur = []; continue
        cur.append(c)
    cur = ''.join(cur)
    if js_trim(cur) != '' or len(args) > 0:
        args.append(cur)
    return [js_trim(a) for a in args]


def match_paren(txt, i):
    depth, j, in_str, q, esc, n = 0, i, False, '', False, len(txt)
    while j < n:
        c = txt[j]
        if in_str:
            if esc: esc = False
            elif c == '\\': esc = True
            elif c == q: in_str = False
            j += 1
            continue
        if c == '"' or c == "'":
            in_str = True; q = c; j += 1; continue
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                j += 1
                break
        j += 1
    return j


def dominant_cat(cats):
    for c in cats:
        if c != 'url': return c
    return cats[0] if cats else 'credential'


def note_from_cats(cats):
    has_key = any(c != 'url' for c in cats)
    has_url = 'url' in cats
    if has_key and has_url: return 'Credential literal and internal host redacted'
    if has_url: return 'Internal hostname or IP replaced with [HOST]'
    return 'Credential value redacted'


def nm(el):
    n = el.getAttribute('name') if el.nodeType == 1 else ''
    return ' [' + n + ']' if n else ''


def location_of(el):
    parts, n, depth = [], el.parentNode, 0
    while n is not None and n.nodeType == 1 and depth < 10:
        tag, name = n.tagName, n.getAttribute('name') or ''
        if name: parts.insert(0, tag + '[' + name + ']')
        elif tag in ('Script', 'Step', 'Field', 'Layout', 'CustomFunction'): parts.insert(0, tag)
        n = n.parentNode
        depth += 1
    return ' \u203a '.join(parts[-3:])


# Split FileMaker calc text into code and comment spans, so the credential
# passes can skip documentation. Recognises /* */ and // comments, and ignores
# comment markers that appear inside string literals.
def split_comments(text):
    spans, cur = [], []
    mode, in_str, q, esc, i, n = 'code', False, '', False, 0, len(text)

    def flush(kind):
        if cur: spans.append((kind, ''.join(cur)))
        cur.clear()

    while i < n:
        c = text[i]
        c2 = text[i + 1] if i + 1 < n else ''
        if mode == 'code':
            if in_str:
                cur.append(c)
                if esc: esc = False
                elif c == '\\': esc = True
                elif c == q: in_str = False
                i += 1
                continue
            if c == '"' or c == "'":
                in_str = True; q = c; cur.append(c); i += 1; continue
            if c == '/' and c2 == '*':
                flush('code'); cur.append('/*'); mode = 'block'; i += 2; continue
            if c == '/' and c2 == '/':
                flush('code'); cur.append('//'); mode = 'line'; i += 2; continue
            cur.append(c); i += 1
            continue
        if mode == 'block':
            if c == '*' and c2 == '/':
                cur.append('*/'); flush('comment'); mode = 'code'; i += 2; continue
            cur.append(c); i += 1
            continue
        if c == '\n' or c == '\r':
            flush('comment'); cur.append(c); mode = 'code'; i += 1; continue
        cur.append(c); i += 1
    flush('code' if mode == 'code' else 'comment')
    return spans


def is_private_ip(ip):
    try:
        p = [int(x) for x in ip.split('.')]
    except ValueError:
        return False
    if len(p) != 4 or any(x > 255 for x in p): return False
    return (p[0] == 10) or (p[0] == 127) or (p[0] == 192 and p[1] == 168) or (p[0] == 172 and 16 <= p[1] <= 31) or (p[0] == 169 and p[1] == 254) or (p[0] == 100 and 64 <= p[1] <= 127)


_IPV4_RE = jsre(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_INTERNAL_TLD_RE = jsre(r'\.(local|internal|lan|intranet|corp|home|test|example|invalid)$', re.I)


# Only internal-looking hosts are redacted: private IPs, single-label hosts
# (http://server1/), and internal-style TLDs. Public domains are left alone.
def is_internal_host(host):
    if _IPV4_RE.search(host): return is_private_ip(host)
    if '.' not in host: return True
    return bool(_INTERNAL_TLD_RE.search(host))


_HDR_AUTH_RE = jsre(r'''((?:Proxy-)?Authorization\s*[:=]\s*\\?["']?\s*(?:Bearer|Basic|Token|Digest|OAuth)\s+)([^\s"'\\;,&]+)''', re.I)
_HDR_KEY_RE = jsre(r'''((?:X-)?(?:API[_-]?Key|Auth[_-]?Token|Access[_-]?Token|Functions-Key)\s*:\s*\\?["']?\s*)([^\s"'\\;,&]+)''', re.I)
_HDR_APIM_RE = jsre(r'''(Ocp-Apim-Subscription-Key\s*:\s*\\?["']?\s*)([^\s"'\\;,&]+)''', re.I)
_HDR_COOKIE_RE = jsre(r'''((?:Set-)?Cookie\s*:\s*)([^"'\\\r\n]+)''', re.I)
_HDR_COOKIE_DONE_RE = jsre(r'^\[REDACTED\]\s*$')
_HDR_CURLU_RE = jsre(r'''((?:^|[\s"'])(?:-u|--user|--proxy-user)\s+\\?["']?)([^\s"'\\:;]+):([^\s"'\\;]+)''')


# Redact credentials that ride inside HTTP header text. These show up as
# plain text inside cURL option literals (Insert from URL), MBS CURL header
# options and concatenated header calculations, so the keyword = "value"
# pass never sees them: the header name identifies the value as a credential
# regardless of the value's shape. This is the same failure class as the
# original SFTP incident, keyed on the consumer rather than the value.
# Handles the escaped-quote form (-H \"Authorization: Bearer x\") because it
# runs on raw code-span text, not per string literal: the naive literal
# splitter in the known-key pass cannot see inside escaped quotes at all.
# Returns { text, count, cats }.
def redact_header_creds(txt):
    count = [0]
    cats = []
    t = txt

    def pre_val(cat):
        def f(m):
            if m.group(2) == '[REDACTED]': return m.group(0)
            count[0] += 1; cats.append(cat)
            return m.group(1) + '[REDACTED]'
        return f

    # Authorization / Proxy-Authorization with a scheme keyword. Covers the
    # header form (Authorization: Bearer x), the assignment form
    # (Authorization = "Basic x") and the escaped cURL form. The scheme word
    # is kept as context, only the credential after it is redacted.
    t = _HDR_AUTH_RE.sub(pre_val('token'), t)

    # API-key style headers. Colon form only: the assignment form of these
    # names is already handled by the keyword pass (they all contain key,
    # token or api). Header names are a curated list, not a guess.
    t = _HDR_KEY_RE.sub(pre_val('api_key'), t)
    t = _HDR_APIM_RE.sub(pre_val('api_key'), t)

    # Cookie / Set-Cookie headers: session cookies ARE credentials, and
    # copied request headers in debugging XML carry them. The whole value is
    # redacted; it stops at a quote, backslash (escaped quote or \r\n in a
    # FileMaker string literal) or a real newline.
    def cookie(m):
        if _HDR_COOKIE_DONE_RE.search(m.group(2)): return m.group(0)
        count[0] += 1; cats.append('token')
        return m.group(1) + '[REDACTED]'
    t = _HDR_COOKIE_RE.sub(cookie, t)

    # cURL user options: -u / --user / --proxy-user user:password. The
    # username is kept as context, the password is redacted.
    def curl_user(m):
        if m.group(3) == '[REDACTED]': return m.group(0)
        count[0] += 1; cats.append('password')
        return m.group(1) + m.group(2) + ':[REDACTED]'
    t = _HDR_CURLU_RE.sub(curl_user, t)

    return {'text': t, 'count': count[0], 'cats': cats}


_URL_USERINFO_RE = jsre(r'''([A-Za-z][A-Za-z0-9+.-]*:\/\/)([^\/\s:@"'\\]+):([^\/\s@"'\\]+)@''')
_URL_QUERY_RE = jsre(r'''([?&](?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|refresh[_-]?token|id[_-]?token|token|key|secret|client[_-]?secret|password|pwd|passwd|sig|signature|sas|code|phpsessid|jsessionid|session[_-]?id)=)([^&\s"'\\<>#]+)''', re.I)


# Redact secrets that live inside URLs themselves. Two shapes:
#   scheme://user:password@host   any scheme (https, ftp, sftp, jdbc:mysql,
#                                 postgres, mongodb+srv...), username kept,
#                                 password redacted
#   ?api_key=value / &token=...   the query parameter NAME marks the value
#                                 as a credential, so it is redacted even
#                                 when the host is public and stays visible
# This generalises the webhook-URL insight: a URL can itself carry auth.
# Returns { text, count, cats }.
def redact_url_secrets(txt):
    count = [0]
    cats = []
    t = txt

    # Userinfo passwords, any scheme.
    def userinfo(m):
        if m.group(3) == '[REDACTED]': return m.group(0)
        count[0] += 1; cats.append('password')
        return m.group(1) + m.group(2) + ':[REDACTED]@'
    t = _URL_USERINFO_RE.sub(userinfo, t)

    # Secret-bearing query parameters. The name list is deliberately broad
    # (key= and code= will over-redact occasionally); for a scrubber that is
    # the right failure direction, and every hit is listed in the findings.
    def query(m):
        if m.group(2) == '[REDACTED]': return m.group(0)
        count[0] += 1; cats.append(categ_from_name(m.group(1)))
        return m.group(1) + '[REDACTED]'
    t = _URL_QUERY_RE.sub(query, t)

    return {'text': t, 'count': count[0], 'cats': cats}


_PRINTABLE_RE = jsre(r'^[\x20-\x7e]+$')
_USERPASS_RE = jsre(r'^[^:\s]{1,64}:[^\s].{0,127}$')


# Decode a base64-looking token and decide whether it hides a user:password
# pair. Hardcoded Basic-auth values often ride as bare base64 literals
# assigned to innocently named variables, where no keyword or key shape can
# see them. The decode is the only reliable detector: printable ASCII with a
# colon splitting two non-empty halves is the user:pass shape. Strings that
# decode to JSON or XML (a lone JWT segment, an encoded payload) start with
# { or < and are excluded, since those are data, not credentials.
def is_base64_user_pass(token):
    # atob throws on non-base64 input, so a failed decode means "not a credential"
    try:
        if len(token) % 4 != 0: return False
        decoded = base64.b64decode(token).decode('latin-1')
        if len(decoded) < 6 or len(decoded) > 194: return False
        # printable ASCII only; binary data decodes are not credentials
        if not _PRINTABLE_RE.search(decoded): return False
        # JSON/XML payloads (JWT segments, encoded bodies) are excluded
        if decoded[0] == '{' or decoded[0] == '<': return False
        # the user:pass shape: non-empty user, a colon, non-empty password
        return bool(_USERPASS_RE.search(decoded))
    except Exception:
        return False


_DQ_LIT_RE = jsre(r'"([^"]*)"')
_SQ_LIT_RE = jsre(r"'([^']*)'")
_DQ_ESC_LIT_RE = jsre(r'"((?:[^"\\]|\\.)*)"')
_B64_RUN_RE = jsre(r'[A-Za-z0-9+\/]{12,}={0,2}')
_HOST_RE = jsre(r'''((?:https?|ftps?|sftp|scp|smb|ldaps?|wss?|fmp\d*|fmnet|filewin|filemac|file):\/{1,3}(?:[^\s"'\/@]*@)?)([a-zA-Z0-9._-]+)((?::\d+)?(?:\/[^\s"']*)?)''', re.I)
_UNC_RE = jsre(r'(\\{2,})([a-zA-Z0-9._-]+)(?=\\)')
_IP_RE = jsre(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
_HOME_RE = jsre(r'(\/(?:Users|home)\/)([a-zA-Z0-9._-]+)')
_WINHOME_RE = jsre(r'([a-zA-Z]:\\{1,2}Users\\{1,2})([a-zA-Z0-9._-]+)')
_WINHOME_KEEP_RE = jsre(r'^(Public|Default)$', re.I)
_AZ_KEY_RE = jsre(r'''(AccountKey\s*=\s*)[^;"'\s]+''', re.I)
_AZ_SAS_RE = jsre(r'''(SharedAccessSignature\s*=\s*)[^;"'\s]+''', re.I)


@functools.lru_cache(maxsize=None)
def _kw_regexes(alt):
    return (
        jsre(r'(^|[^\w$.])((?:\$\$?)?[\w.]*(?:' + alt + r')[\w.]*[ \t]*[\r\n]*[ \t]*=[ \t]*[\r\n]*[ \t]*)"((?:[^"\\]|\\.)*)"', re.I),
        jsre(r"(^|[^\w$.])((?:\$\$?)?[\w.]*(?:" + alt + r")[\w.]*[ \t]*[\r\n]*[ \t]*=[ \t]*[\r\n]*[ \t]*)'((?:[^'\\]|\\.)*)'", re.I),
        jsre(r'(\\"[\w.-]*(?:' + alt + r')[\w.-]*\\"[ \t]*:[ \t]*\\")((?:[^"\\]|\\[^"])*)(\\")', re.I),
        jsre(r'("[\w.-]*(?:' + alt + r')[\w.-]*"[ \t]*:[ \t]*")((?:[^"\\]|\\.)*)(")', re.I),
    )


# Redact credential literals inside one calculation string. Returns { text, count, cats }.
# opts carries the v1.4 additions: jsoncred (JSON "key":"value" colon form),
# b64 (base64 user:pass decode heuristic), userpath ([USER] in home paths).
def redact_calc_text(txt, known_key_re, kw_parts, do_url, do_azure, do_header, do_url_secret, opts=None):
    opts = opts or {}
    count = [0]
    cats = []

    # Known key formats run across the WHOLE text, comments included. Near-zero
    # false positives, and a real key pasted into a comment is still a leak.
    base = txt
    if known_key_re:
        def kk(q):
            def f(m):
                if known_key_re.search(m.group(1)):
                    count[0] += 1; cats.append('api_key')
                    return q + '[REDACTED]' + q
                return m.group(0)
            return f
        base = _DQ_LIT_RE.sub(kk('"'), base)
        base = _SQ_LIT_RE.sub(kk("'"), base)

    # Keyword assignments and host/IP redaction run only OUTSIDE comments, so
    # documentation blocks in custom functions are not flagged.
    def code_span(t):
        if kw_parts:
            re_d, re_s, re_je, re_jp = _kw_regexes('|'.join(kw_parts))
            # Optional $/$$ prefix so Let() locals (no prefix) are caught as well as $vars.
            def assign(q):
                def f(m):
                    if m.group(3) == '[REDACTED]': return m.group(0)
                    count[0] += 1; cats.append(categ_from_name(m.group(2)))
                    return m.group(1) + m.group(2) + q + '[REDACTED]' + q
                return f
            t = re_d.sub(assign('"'), t)
            t = re_s.sub(assign("'"), t)

        # JSON colon form: the keyword=value pass above requires an equals
        # sign, so a credential inside a hardcoded JSON request body
        # ("password":"hunter2") sailed straight through. Two shapes exist in
        # calc text: the escaped form (\"password\":\"x\") inside a FileMaker
        # string literal, which is how Insert from URL --data payloads are
        # written, and the plain form ("password":"x") in raw JSON that sits
        # outside string literals (custom function bodies, pasted samples).
        # The escaped form is matched first, because its \" sequences would
        # otherwise confuse the plain-form match.
        if opts.get('jsoncred') and kw_parts:
            def json_pair(m):
                if m.group(2) == '[REDACTED]': return m.group(0)
                count[0] += 1; cats.append(categ_from_name(m.group(1)))
                return m.group(1) + '[REDACTED]' + m.group(3)
            # Escaped form: \"key\" : \"value\" -- the value runs until the
            # next \" sequence. A backslash NOT followed by a quote is legal
            # inside the value (e.g. \\n), hence the [^"\\]|\\[^"] body.
            t = re_je.sub(json_pair, t)
            # Plain form: "key" : "value" with real quotes.
            t = re_jp.sub(json_pair, t)

        # Base64 user:pass literals: a hardcoded "Basic dXNlcjpwYXNz" is
        # caught by the header pass when the Authorization: prefix is
        # present, but the bare token assigned to $auth has no keyword and
        # no key shape. Each base64-looking run inside a string literal is
        # decoded, and anything that comes back as printable user:pass is
        # redacted in place, keeping surrounding text (like the word Basic)
        # as context.
        if opts.get('b64'):
            def lit(m):
                inner = m.group(1)
                if '[REDACTED]' in inner: return m.group(0)
                def tok(mt):
                    if not is_base64_user_pass(mt.group(0)): return mt.group(0)
                    count[0] += 1; cats.append('password')
                    return '[REDACTED]'
                replaced = _B64_RUN_RE.sub(tok, inner)
                return m.group(0) if replaced == inner else '"' + replaced + '"'
            t = _DQ_ESC_LIT_RE.sub(lit, t)

        # Header and URL-secret passes run AFTER the keyword pass, so an
        # Authorization = "Bearer x" assignment already redacted whole by
        # the keyword pass is not counted twice, and BEFORE host redaction,
        # so a userinfo password is gone before the host is evaluated.
        if do_header:
            rh = redact_header_creds(t)
            t = rh['text']; count[0] += rh['count']
            cats.extend(rh['cats'])
        if do_url_secret:
            ru = redact_url_secrets(t)
            t = ru['text']; count[0] += ru['count']
            cats.extend(ru['cats'])

        if do_url:
            # The optional userinfo group skips an already-redacted
            # user:[REDACTED]@ prefix so the REAL host after the @ still
            # gets the [HOST] treatment; without it the username was being
            # matched as the host and the internal hostname leaked.
            # Scheme list widened in v1.4: the old https?-only match let
            # fmnet:/fms.corp.local/CRM, fmp://host/file, sftp:// and
            # filewin:// paths carry internal hostnames straight through.
            # fmnet uses a single slash, hence :\/{1,3}.
            def host(m):
                sch, h, rest = m.group(1), m.group(2), m.group(3)
                if h == '[HOST]' or not is_internal_host(h): return m.group(0)
                count[0] += 1; cats.append('url')
                return sch + '[HOST]' + (rest or '')
            t = _HOST_RE.sub(host, t)
            # UNC paths: \\SERVER\share. In calc text the backslashes are
            # doubled by FileMaker string escaping, so 2+ backslashes
            # followed by a host followed by a backslash is the shape.
            def unc(m):
                if m.group(2) == '[HOST]' or not is_internal_host(m.group(2)): return m.group(0)
                count[0] += 1; cats.append('url')
                return m.group(1) + '[HOST]'
            t = _UNC_RE.sub(unc, t)
            def ip(m):
                if not is_private_ip(m.group(1)): return m.group(0)
                count[0] += 1; cats.append('url')
                return '[HOST]'
            t = _IP_RE.sub(ip, t)
            # Home-directory paths identify employees by their machine
            # account name: /Users/jsmith/, /home/jsmith/, C:\Users\jsmith\.
            # The username becomes [USER]; the rest of the path is kept,
            # since the structure is usually needed to understand the calc.
            def home(m):
                user = m.group(2)
                if user == '[USER]' or user == 'Shared': return m.group(0)
                count[0] += 1; cats.append('url')
                return m.group(1) + '[USER]'
            t = _HOME_RE.sub(home, t)
            def winhome(m):
                user = m.group(2)
                if user == '[USER]' or _WINHOME_KEEP_RE.search(user): return m.group(0)
                count[0] += 1; cats.append('url')
                return m.group(1) + '[USER]'
            t = _WINHOME_RE.sub(winhome, t)
        if do_azure:
            # Azure storage / SAS: redact the secret segment, keep endpoint + account
            # name as context. Mirrors the connection-string password= handling.
            def az(m):
                count[0] += 1; cats.append('secret')
                return m.group(1) + '[REDACTED]'
            t = _AZ_KEY_RE.sub(az, t)
            t = _AZ_SAS_RE.sub(az, t)
        return t

    out = ''.join(sp_text if kind == 'comment' else code_span(sp_text) for kind, sp_text in split_comments(base))

    return {'text': out, 'count': count[0], 'cats': cats}


# Redact every quoted literal (used for a Set Variable whose NAME looks like a secret).
def redact_all_literals(txt):
    count = [0]

    def lit(q):
        def f(m):
            inner = m.group(1)
            if inner == '' or inner == '[REDACTED]': return m.group(0)
            count[0] += 1
            return q + '[REDACTED]' + q
        return f
    r = _DQ_LIT_RE.sub(lit('"'), txt)
    r = _SQ_LIT_RE.sub(lit("'"), r)
    return {'text': r, 'count': count[0]}


# Redact plugin licence/registration keys passed as POSITIONAL arguments, which
# the keyword=value pass cannot see. Handles MBS("Register"; ...), BE_Register(...)
# and any *_Register(...) activation call. Walks the balanced argument list with
# string awareness and redacts each string literal except the MBS "Register"
# selector. Returns { text, count }.
def redact_register_calls(txt):
    total = 0
    out = []
    # Only scan code spans, never documentation comments.
    for kind, sp_text in split_comments(txt):
        if kind == 'comment':
            out.append(sp_text)
            continue
        r = scan_register(sp_text)
        total += r['count']
        out.append(r['text'])
    return {'text': ''.join(out), 'count': total}


_REG_NAME_RE = jsre(r'\b(MBS|[A-Za-z][A-Za-z0-9]*_Register)\b')
_MBS_REGISTER_RE = jsre(r'''^\(\s*(["'])Register\1''', re.I)
_ANY_LIT_RE = jsre(r'''"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*\'''')
_REGISTER_WORD_RE = jsre(r'^Register$', re.I)


def scan_register(txt):
    count = 0
    result, last, pos = [], 0, 0
    while True:
        m = _REG_NAME_RE.search(txt, pos)
        if not m:
            break
        pos = m.end()
        name = m.group(1)
        # Skip whitespace to the opening paren; bail if this isn't a call.
        i = m.end()
        while i < len(txt) and txt[i] in _JS_WS_CHARS:
            i += 1
        if i >= len(txt) or txt[i] != '(':
            continue

        # Find the matching close paren, ignoring parens inside string literals.
        j = match_paren(txt, i)
        span = txt[i:j]   # includes the surrounding ( )

        # MBS is only a registration call when the first argument is "Register".
        if name == 'MBS' and not _MBS_REGISTER_RE.search(span):
            continue

        local = [0]

        def lit(mm):
            s = mm.group(0)
            inner = s[1:-1]
            if _REGISTER_WORD_RE.search(inner): return s          # keep MBS selector
            if inner == '' or inner == '[REDACTED]': return s
            local[0] += 1
            return s[0] + '[REDACTED]' + s[0]
        new_span = _ANY_LIT_RE.sub(lit, span)
        if local[0] > 0:
            result.append(txt[last:i] + new_span)
            last = j
            count += local[0]
            pos = j   # don't rescan inside the call we just handled
    result.append(txt[last:])
    return {'text': ''.join(result), 'count': count}


# calculations in CDATA; keeping CDATA avoids re-escaping < > & into entities.
def set_calc_text(calc_el, new_text, doc):
    use_cdata = calc_el.firstChild is not None and calc_el.firstChild.nodeType == 4
    while calc_el.firstChild is not None:
        calc_el.removeChild(calc_el.firstChild)
    calc_el.appendChild(doc.createCDATASection(new_text) if use_cdata else doc.createTextNode(new_text))


# ── DOM ──────────────────────────────────────────────────────
def descendants(el):
    stack = list(reversed(el.childNodes))
    while stack:
        n = stack.pop()
        if n.nodeType == 1:
            yield n
            stack.extend(reversed(n.childNodes))


def text_nodes(el):
    stack = list(reversed(el.childNodes))
    while stack:
        n = stack.pop()
        if n.nodeType in (3, 4):
            yield n
        elif n.nodeType == 1:
            stack.extend(reversed(n.childNodes))


def text_content(el):
    if el.nodeType in (3, 4):
        return el.data
    return ''.join(n.data for n in text_nodes(el))


def set_text_content(el, s, doc):
    while el.firstChild is not None:
        el.removeChild(el.firstChild)
    if s:
        el.appendChild(doc.createTextNode(s))


def first_desc(el, tag):
    for d in descendants(el):
        if d.tagName == tag:
            return d
    return None


def child(el, tag):
    for c in el.childNodes:
        if c.nodeType == 1 and c.tagName == tag:
            return c
    return None


def element_children(el):
    return [c for c in el.childNodes if c.nodeType == 1]


def has_ancestor(el, tag):
    n = el.parentNode
    while n is not None and n.nodeType == 1:
        if n.tagName == tag:
            return True
        n = n.parentNode
    return False


def value_calc(el):
    for d in descendants(el):
        if d.tagName == 'Calculation' and d.parentNode is not None and d.parentNode.nodeType == 1 and d.parentNode.tagName == 'Value':
            return d
    return None


def attr_items(el):
    return list(el.attributes.items()) if el.attributes is not None else []


# ── ENGINE ───────────────────────────────────────────────────
_SET_FIELD_RE = jsre(r'^Set Field$', re.I)
_SET_FIELD_BY_NAME_RE = jsre(r'^Set Field By Name$', re.I)
_INSERT_TEXT_RE = jsre(r'^Insert Text$', re.I)
_PEM_MARK_RE = jsre(r'-----BEGIN[A-Z0-9 ]*PRIVATE KEY-----')
_VAR_NAME_CLEAN_RE = jsre(r'\[.*$')
_DOLLAR_PREFIX_RE = jsre(r'^\$+')
_CURL_CALL_RE = jsre(r'CURL\.SetOption(Password|UserName|XOAuth2Bearer)', re.I)
_MBS_RE = jsre(r'\bMBS\b')
_VAR_ARG_RE = jsre(r'^\${1,2}[A-Za-z_][A-Za-z0-9_]*$')
_CONN_KEY_RE = jsre(r'(?:password|pwd|accountkey|sharedaccesssignature|accesstoken|authenticationtoken)\s*=', re.I)
_CONN_KEY_SUB_RE = jsre(r'''(password|pwd|accountkey|sharedaccesssignature|accesstoken|authenticationtoken)(\s*=\s*)[^;,'"]+''', re.I)
_CONN_USERINFO_RE = jsre(r'''([A-Za-z][A-Za-z0-9+.-]*:\/\/)([^\/\s:@"'\\]+):([^\/\s@"'\\]+)@''')
_REDACTED_ANY_RE = jsre(r'\[REDACTED\]')
_EMAIL_RE = jsre(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
_CARD_RE = jsre(r'(^|[^\d-])((?:\d[ -]?){12,18}\d)(?![\d-])')
_CARD_SEP_RE = jsre(r'[ -]')


def _clean_var(name):
    return js_trim(_VAR_NAME_CLEAN_RE.sub('', _DOLLAR_PREFIX_RE.sub('', name, count=1), count=1))


# Single redact-first pass over a clone. Returns { clone, changes, tally, anyChange }.
def redact_document(source_doc, cfg):
    doc = source_doc.cloneNode(True)
    root = doc.documentElement
    changes = []
    tally = {'api_key': 0, 'token': 0, 'password': 0, 'secret': 0, 'smtp': 0, 'oauth': 0, 'credential': 0, 'license': 0, 'url': 0, 'pii': 0, 'total': 0}

    def tally1(c, n):
        tally[c] = tally.get(c, 0) + n
        tally['total'] += n

    known_key_re = cfg['known_key_re']
    kw_parts = cfg['kw_parts']
    cred_name_re = jsre('(?:' + '|'.join(cfg['cred_name_kws']) + ')', re.I) if cfg.get('cred_name_kws') else None
    done = set()

    all_els = list(descendants(root))
    calcs = [e for e in all_els if e.tagName == 'Calculation']
    custom_fns = [e for e in all_els if e.tagName == 'CustomFunction' and has_ancestor(e, 'CalcsForCustomFunctions')]
    steps_all = [e for e in all_els if e.tagName == 'Step']

    def process_calc_el(el, kind_label):
        if el in done: return
        txt = text_content(el)
        if not txt: return
        r = redact_calc_text(txt, known_key_re, kw_parts if cfg['inline'] else None, cfg['url'], cfg['azure'], cfg['headercred'], cfg['urlsecret'],
                             {'jsoncred': cfg['jsoncred'], 'b64': cfg['b64']})
        if r['count'] > 0:
            set_calc_text(el, r['text'], doc); done.add(el)
            for c in r['cats']: tally1(c, 1)
            changes.append({'severity': 'high' if any(c != 'url' for c in r['cats']) else 'medium',
                            'kind': kind_label or 'Calculation literal', 'category': dominant_cat(r['cats']),
                            'location': location_of(el), 'count': r['count'], 'before': preview_redactions(r['text']), 'note': note_from_cats(r['cats'])})

    # 0: Configure AI Account (step id 212)
    for step in [s for s in steps_all if s.getAttribute('id') == '212']:
        for el in [d for d in descendants(step) if d.tagName == 'Calculation']:
            if el in done or not js_trim(text_content(el)): continue
            set_calc_text(el, '"[REDACTED]"', doc); done.add(el); tally1('api_key', 1)
            changes.append({'severity': 'high', 'kind': 'AI account API key', 'category': 'api_key', 'location': location_of(el), 'count': 1, 'before': '"[REDACTED]"', 'note': 'Configure AI Account step value'})

    # 1: Set Variable (step id 141) whose name looks like a credential
    if cred_name_re:
        for step in [s for s in steps_all if s.getAttribute('id') == '141']:
            name_el = first_desc(step, 'Name')
            var_name = text_content(name_el) if name_el is not None else ''
            clean = _clean_var(var_name)
            if not cred_name_re.search(clean): continue
            v = value_calc(step)
            if v is None or v in done: continue
            txt = text_content(v)
            cat = categ_from_name(var_name)
            if is_bare_string(txt):
                set_calc_text(v, '"[REDACTED]"', doc); done.add(v); tally1(cat, 1)
                changes.append({'severity': 'high', 'kind': 'Set Variable (credential name)', 'category': cat, 'location': location_of(v), 'count': 1, 'before': '"[REDACTED]"', 'note': 'Variable "' + js_trim(var_name) + '" set to a literal'})
            else:
                r = redact_all_literals(txt)
                if r['count'] > 0:
                    set_calc_text(v, r['text'], doc); done.add(v); tally1(cat, r['count'])
                    changes.append({'severity': 'high', 'kind': 'Set Variable (credential name)', 'category': cat, 'location': location_of(v), 'count': r['count'], 'before': preview_redactions(r['text']), 'note': 'Literals in a credential-named variable redacted'})

    # 1.2: credential-named ELEMENTS. FileMaker's own steps embed passwords
    # structurally: Re-Login with specified credentials, Add Account, Reset
    # Account Password, Change Password, Send Mail SMTP authentication and
    # ODBC steps all wrap the password in an element NAMED for what it is,
    # like <Password><Calculation>"hunter2"</Calculation></Password>. The
    # literal inside has no keyword and usually no shape, so every earlier
    # pass missed it; the element name is the identification, exactly as the
    # attribute-name pass already works. Account-name elements are left
    # alone by design (the keyword list has never included "account").
    if cfg['credtarget'] and cred_name_re:
        for el in all_els:
            if not cred_name_re.search(el.tagName): continue
            cat = categ_from_name(el.tagName)
            calc = child(el, 'Calculation') or (first_desc(el, 'Calculation') if el.tagName != 'Calculation' else None)
            if calc is not None:
                if calc in done: continue
                txt = text_content(calc)
                if not js_trim(txt): continue
                if is_bare_string(txt):
                    set_calc_text(calc, '"[REDACTED]"', doc); done.add(calc); tally1(cat, 1)
                    changes.append({'severity': 'high', 'kind': 'Credential-named element', 'category': cat, 'location': location_of(calc), 'count': 1, 'before': '"[REDACTED]"', 'note': '<' + el.tagName + '> element (Re-Login / Add Account / SMTP / ODBC class) set to a literal'})
                else:
                    r = redact_all_literals(txt)
                    if r['count'] > 0:
                        set_calc_text(calc, r['text'], doc); done.add(calc); tally1(cat, r['count'])
                        changes.append({'severity': 'high', 'kind': 'Credential-named element', 'category': cat, 'location': location_of(calc), 'count': r['count'], 'before': preview_redactions(r['text']), 'note': 'Literals inside a <' + el.tagName + '> element redacted'})
            elif len(element_children(el)) == 0:
                # A text-only credential element (no Calculation wrapper).
                # Variable and field references are left visible, since the
                # value lives elsewhere and the reference is the useful context.
                tv = js_trim(text_content(el))
                if not tv or tv == '[REDACTED]' or tv[0] == '$' or '::' in tv: continue
                set_text_content(el, '[REDACTED]', doc); tally1(cat, 1)
                changes.append({'severity': 'high', 'kind': 'Credential-named element', 'category': cat, 'location': location_of(el), 'count': 1, 'before': '[REDACTED]', 'note': '<' + el.tagName + '> element contained a bare value'})

    # 1.3: Set Field / Insert Text whose TARGET FIELD is credential-named.
    # Set Field [ Users::Password ; "temp123" ] carries no keyword in the
    # value calc; the target field name is the identification, mirroring the
    # Set Variable pass above. Matched by step NAME rather than id so the
    # pass survives any renumbering and covers Set Field By Name too.
    if cfg['credtarget'] and cred_name_re:
        for step in steps_all:
            step_name = step.getAttribute('name') or ''
            is_set_field = bool(_SET_FIELD_RE.search(step_name))
            is_set_field_by_name = bool(_SET_FIELD_BY_NAME_RE.search(step_name))
            is_insert_text = bool(_INSERT_TEXT_RE.search(step_name))
            if not is_set_field and not is_set_field_by_name and not is_insert_text: continue
            # For Set Field / Insert Text the target is a <Field name="...">
            # child; for Set Field By Name the target is itself a calc, so
            # any non-Value calculation naming a credential field counts.
            target_hit = False
            fld = child(step, 'Field')
            if fld is not None and cred_name_re.search(fld.getAttribute('name') or ''): target_hit = True
            if is_set_field_by_name and not target_hit:
                for c in [d for d in descendants(step) if d.tagName == 'Calculation']:
                    if c.parentNode is not None and c.parentNode.nodeType == 1 and c.parentNode.tagName == 'Value': continue
                    if cred_name_re.search(text_content(c)): target_hit = True
            if not target_hit: continue
            fld_name = (fld.getAttribute('name') or '') if fld is not None else '(calculated target)'
            cat = categ_from_name(fld_name) if categ_from_name(fld_name) != 'credential' else 'password'
            if is_insert_text:
                text_el = child(step, 'Text')
                if text_el is not None and js_trim(text_content(text_el)) and text_content(text_el) != '[REDACTED]':
                    set_text_content(text_el, '[REDACTED]', doc); tally1(cat, 1)
                    changes.append({'severity': 'high', 'kind': 'Insert Text into credential field', 'category': cat, 'location': location_of(text_el), 'count': 1, 'before': '[REDACTED]', 'note': 'Text inserted into field "' + fld_name + '"'})
                continue
            v = value_calc(step)
            if v is None or v in done: continue
            txt = text_content(v)
            if not js_trim(txt): continue
            if is_bare_string(txt):
                set_calc_text(v, '"[REDACTED]"', doc); done.add(v); tally1(cat, 1)
                changes.append({'severity': 'high', 'kind': 'Set Field (credential field)', 'category': cat, 'location': location_of(v), 'count': 1, 'before': '"[REDACTED]"', 'note': 'Literal written to field "' + fld_name + '"'})
            else:
                r = redact_all_literals(txt)
                if r['count'] > 0:
                    set_calc_text(v, r['text'], doc); done.add(v); tally1(cat, r['count'])
                    changes.append({'severity': 'high', 'kind': 'Set Field (credential field)', 'category': cat, 'location': location_of(v), 'count': r['count'], 'before': preview_redactions(r['text']), 'note': 'Literals written to field "' + fld_name + '" redacted'})

    # 1.4: PEM private-key blocks. The base64 body has no safe shape of its own,
    # so a calc containing a key marker is treated as a key-handling calc and ALL
    # its literals are redacted. Catches keys split across concatenated literals.
    if cfg['pem']:
        def process_pem(el, kind_label):
            if el in done: return
            txt = text_content(el)
            if not _PEM_MARK_RE.search(txt): return
            r = redact_all_literals(txt)
            if r['count'] > 0:
                set_calc_text(el, r['text'], doc); done.add(el); tally1('secret', r['count'])
                changes.append({'severity': 'high', 'kind': kind_label or 'PEM private key', 'category': 'secret',
                                'location': location_of(el), 'count': r['count'], 'before': preview_redactions(r['text']),
                                'note': 'Private-key block \u2014 all literals in the calc redacted'})
        for el in calcs: process_pem(el, None)
        for el in custom_fns: process_pem(el, 'PEM private key (custom function)')

    # 1.5: plugin registration calls (positional args, invisible to keyword=value).
    # Runs first and does NOT mark the node done, so a real key elsewhere in the
    # same calc is still caught by the generic pass below.
    if cfg['plugin']:
        def process_register(el, kind_label):
            txt = text_content(el)
            if not txt: return
            r = redact_register_calls(txt)
            if r['count'] > 0:
                set_calc_text(el, r['text'], doc); tally1('license', r['count'])
                changes.append({'severity': 'medium', 'kind': kind_label or 'Plugin registration key', 'category': 'license',
                                'location': location_of(el), 'count': r['count'], 'before': preview_redactions(r['text']),
                                'note': 'Literal argument(s) to a *_Register / MBS("Register") call \u2014 verify before sharing'})
        for el in calcs:
            if el not in done: process_register(el, None)
        for el in custom_fns:
            if el not in done: process_register(el, 'Plugin registration key (custom function)')

    # 1.6: CURL/SFTP credential-consuming calls (MBS CURL.SetOptionPassword,
    # CURL.SetOptionUserName, CURL.SetOptionXOAuth2Bearer). These pass a
    # credential as a positional argument, not keyword=value, so the generic
    # passes below can't see them. The argument shows up in three shapes:
    #   literal   MBS("CURL.SetOptionPassword"; $curl; "hunter2")
    #             -> redact right here, same as a Register call.
    #   variable  MBS("CURL.SetOptionPassword"; $curl; $password)
    #             -> the real value isn't in this calc at all. Walk backward
    #             through THIS script's own step list for the nearest
    #             Set Variable [$password; ...] above this step and redact
    #             there instead. This is the fix for the original SFTP
    #             incident: a plain-word password has no shape a value-based
    #             scan can catch, so we key on the credential-consuming call
    #             instead and trace back to where the value actually lives.
    #   field     MBS("CURL.SetOptionPassword"; $curl; Table::Password)
    #             -> nothing to redact; the secret lives in data, not this
    #             file. Flagged so a reviewer knows where it comes from.
    # Scope: the trace only walks the current script's own steps. A variable
    # set by a calling script, or a global $$variable set elsewhere, will not
    # be found -- flagged as unresolved rather than silently missed.
    # Shared by the MBS CURL pass (1.6) and the native-function pass (1.7):
    # walking up to the owning script/step, and tracing a variable argument
    # back to the Set Variable that assigned it within the same script.
    has_script = root.tagName == 'Script' or any(e.tagName == 'Script' for e in all_els)
    script_steps = {}

    def find_enclosing_script(el):
        n = el
        while n is not None:
            if n.nodeType == 1 and n.tagName == 'Script': return n
            n = n.parentNode
        # A bare clipboard paste (a script copied straight out of the Script
        # Workspace, or Andy Kear's own script-XML skill output) has no
        # <Script> wrapper at all -- it's just a flat list of <Step>
        # elements under the fmxmlsnippet root. If the WHOLE document has
        # no <Script> element anywhere, it's safe to treat the root as the
        # script container, since there's only one script's worth of steps
        # in the file. If the document DOES have real <Script> wrappers
        # elsewhere but this particular calc sits outside all of them,
        # that's ambiguous -- don't guess which script it belongs to.
        if not has_script: return doc.documentElement
        return None

    def find_step_ancestor(el):
        n = el
        while n is not None:
            if n.nodeType == 1 and n.tagName == 'Step': return n
            n = n.parentNode
        return None

    def trace_variable_source(var_name, script_el, before_step):
        clean = _clean_var(var_name)
        key = id(script_el)
        if key not in script_steps:
            script_steps[key] = [d for d in descendants(script_el) if d.tagName == 'Step']
        steps = script_steps[key]
        cut_idx = next((k for k, s in enumerate(steps) if s is before_step), -1)
        if cut_idx == -1: cut_idx = len(steps)
        for i in range(cut_idx - 1, -1, -1):
            st = steps[i]
            if st.getAttribute('id') != '141': continue
            name_el = first_desc(st, 'Name')
            st_var = _clean_var(text_content(name_el) if name_el is not None else '')
            if st_var == clean: return value_calc(st)
        return None

    if cfg['curlcred']:
        cred_calls = [
            {'match': jsre(r'CURL\.SetOptionPassword', re.I),      'kind': 'SFTP/CURL password',  'severity': 'high'},
            {'match': jsre(r'CURL\.SetOptionXOAuth2Bearer', re.I), 'kind': 'OAuth bearer token',  'severity': 'high'},
            {'match': jsre(r'CURL\.SetOptionUserName', re.I),      'kind': 'SFTP/CURL username',  'severity': 'medium'},
        ]

        def process_curl_creds(el):
            txt = text_content(el)
            if not txt or not _CURL_CALL_RE.search(txt): return
            step_el = find_step_ancestor(el)
            script_el = find_enclosing_script(step_el) if step_el is not None else None
            pos = 0
            while True:
                m = _MBS_RE.search(txt, pos)
                if not m: break
                pos = m.end()
                i = m.end()
                while i < len(txt) and txt[i] in _JS_WS_CHARS: i += 1
                if i >= len(txt) or txt[i] != '(': continue
                j = match_paren(txt, i)
                span = txt[i + 1:j - 1]
                args = split_top_level_args(span)
                if len(args) < 3: continue
                fn_lit = args[0]
                cred_def = next((c for c in cred_calls if c['match'].search(fn_lit)), None)
                if not cred_def: continue
                value_arg = args[2]
                if is_bare_string(value_arg):
                    q2 = value_arg[0]
                    idx = txt.find(value_arg, i)
                    if idx == -1 or idx > j: continue
                    new_txt = txt[:idx] + q2 + '[REDACTED]' + q2 + txt[idx + len(value_arg):]
                    set_calc_text(el, new_txt, doc); tally1('password', 1)
                    changes.append({'severity': cred_def['severity'], 'kind': cred_def['kind'], 'category': 'password',
                                    'location': location_of(el), 'count': 1, 'before': preview_redactions(new_txt),
                                    'note': 'Literal argument to ' + fn_lit + ' \u2014 verify before sharing'})
                    txt = new_txt
                    pos = idx + 11
                elif _VAR_ARG_RE.search(value_arg):
                    src_calc = trace_variable_source(value_arg, script_el, step_el) if script_el is not None else None
                    if src_calc is not None and src_calc not in done:
                        src_txt = text_content(src_calc)
                        if is_bare_string(src_txt):
                            set_calc_text(src_calc, '"[REDACTED]"', doc); done.add(src_calc); tally1('password', 1)
                            changes.append({'severity': cred_def['severity'], 'kind': cred_def['kind'] + ' (traced to source)', 'category': 'password',
                                            'location': location_of(src_calc), 'count': 1, 'before': '"[REDACTED]"',
                                            'note': 'Variable ' + value_arg + ' is passed to ' + fn_lit + ' \u2014 redacted at its source assignment, not where it\u2019s used'})
                        else:
                            r = redact_all_literals(src_txt)
                            if r['count'] > 0:
                                set_calc_text(src_calc, r['text'], doc); done.add(src_calc); tally1('password', r['count'])
                                changes.append({'severity': cred_def['severity'], 'kind': cred_def['kind'] + ' (traced to source)', 'category': 'password',
                                                'location': location_of(src_calc), 'count': r['count'], 'before': preview_redactions(r['text']),
                                                'note': 'Variable ' + value_arg + ' is passed to ' + fn_lit + ' \u2014 literals in its source assignment redacted'})
                    elif src_calc is None:
                        # Covers two cases equally: a real script where the
                        # variable's source genuinely isn't in this script, and
                        # a document with no usable script context at all (e.g.
                        # a calc sitting outside every <Script> wrapper in a
                        # multi-script file). Either way, say so rather than
                        # going quiet.
                        changes.append({'severity': cred_def['severity'], 'kind': cred_def['kind'] + ' (unresolved)', 'category': 'password',
                                        'location': location_of(el), 'count': 0, 'before': preview_redactions(txt),
                                        'note': 'Variable ' + value_arg + ' is passed to ' + fn_lit + ' but its source could not be found \u2014 check a calling script, a global, or a field, and verify by hand'})
                elif '::' in value_arg:
                    changes.append({'severity': 'medium', 'kind': cred_def['kind'] + ' (field reference)', 'category': 'password',
                                    'location': location_of(el), 'count': 0, 'before': preview_redactions(txt),
                                    'note': 'This call reads its value from field ' + value_arg + ' \u2014 nothing to redact here since the secret lives in your data, not this file, but reviewers should know where it comes from'})
        for el in calcs: process_curl_creds(el)

    # 1.7: native functions that take a credential as a POSITIONAL argument.
    # Same failure class as the MBS CURL calls above: nothing about the
    # value identifies it, the consumer does. Two families are covered:
    #   JSONSetElement ( json ; "apiKey" ; "zK9m..." ; JSONString )
    #     -> the key name identifies the value, exactly like keyword="value"
    #     but with FileMaker's semicolon syntax instead of an equals sign.
    #     Both the flat form and the bracketed [key;value;type] group form
    #     are handled.
    #   CryptEncrypt / CryptDecrypt / CryptAuthCode and their Base64 twins
    #     -> the key argument IS the secret, at a fixed position.
    # Literal arguments are redacted in place; variable arguments are traced
    # back through the script's own steps like the CURL pass; field
    # references are flagged for manual review.
    if cfg['nativecred']:
        # keyIdx is the zero-based argument position of the secret; -1 means
        # JSONSetElement's key/value pair handling applies instead.
        native_cred_fns = [
            {'name': 'JSONSetElement',     'keyIdx': -1, 'kind': 'JSON credential value',   'severity': 'high'},
            {'name': 'CryptEncryptBase64', 'keyIdx': 1,  'kind': 'Encryption key argument', 'severity': 'high'},
            {'name': 'CryptDecryptBase64', 'keyIdx': 1,  'kind': 'Encryption key argument', 'severity': 'high'},
            {'name': 'CryptEncrypt',       'keyIdx': 1,  'kind': 'Encryption key argument', 'severity': 'high'},
            {'name': 'CryptDecrypt',       'keyIdx': 1,  'kind': 'Encryption key argument', 'severity': 'high'},
            {'name': 'CryptAuthCode',      'keyIdx': 2,  'kind': 'HMAC key argument',       'severity': 'high'},
        ]
        fn_name_re = jsre(r'\b(' + '|'.join(f['name'] for f in native_cred_fns) + r')\s*\(', re.I)

        def process_native_creds(el):
            txt = text_content(el)
            if not txt or not fn_name_re.search(txt): return
            step_el = find_step_ancestor(el)
            script_el = find_enclosing_script(step_el) if step_el is not None else None

            # Redact one credential-bearing argument expression, whichever
            # of the three shapes it takes. Returns the (possibly mutated)
            # calc text so the caller can keep scanning the updated string.
            def handle_arg(value_arg, fn_def, fn_label, call_start, call_end, current_txt):
                if is_bare_string(value_arg):
                    q2 = value_arg[0]
                    idx = current_txt.find(value_arg, call_start)
                    if idx == -1 or idx > call_end: return current_txt
                    new_txt = current_txt[:idx] + q2 + '[REDACTED]' + q2 + current_txt[idx + len(value_arg):]
                    set_calc_text(el, new_txt, doc); tally1('password', 1)
                    changes.append({'severity': fn_def['severity'], 'kind': fn_def['kind'], 'category': 'password',
                                    'location': location_of(el), 'count': 1, 'before': preview_redactions(new_txt),
                                    'note': 'Literal argument to ' + fn_label + ' \u2014 verify before sharing'})
                    return new_txt
                if _VAR_ARG_RE.search(value_arg):
                    src_calc = trace_variable_source(value_arg, script_el, step_el) if script_el is not None else None
                    if src_calc is not None and src_calc not in done:
                        src_txt = text_content(src_calc)
                        if is_bare_string(src_txt):
                            set_calc_text(src_calc, '"[REDACTED]"', doc); done.add(src_calc); tally1('password', 1)
                            changes.append({'severity': fn_def['severity'], 'kind': fn_def['kind'] + ' (traced to source)', 'category': 'password',
                                            'location': location_of(src_calc), 'count': 1, 'before': '"[REDACTED]"',
                                            'note': 'Variable ' + value_arg + ' is passed to ' + fn_label + ' \u2014 redacted at its source assignment'})
                        else:
                            r = redact_all_literals(src_txt)
                            if r['count'] > 0:
                                set_calc_text(src_calc, r['text'], doc); done.add(src_calc); tally1('password', r['count'])
                                changes.append({'severity': fn_def['severity'], 'kind': fn_def['kind'] + ' (traced to source)', 'category': 'password',
                                                'location': location_of(src_calc), 'count': r['count'], 'before': preview_redactions(r['text']),
                                                'note': 'Variable ' + value_arg + ' is passed to ' + fn_label + ' \u2014 literals in its source assignment redacted'})
                    elif src_calc is None:
                        changes.append({'severity': fn_def['severity'], 'kind': fn_def['kind'] + ' (unresolved)', 'category': 'password',
                                        'location': location_of(el), 'count': 0, 'before': preview_redactions(current_txt),
                                        'note': 'Variable ' + value_arg + ' is passed to ' + fn_label + ' but its source could not be found \u2014 check a calling script, a global, or a field, and verify by hand'})
                    return current_txt
                if '::' in value_arg:
                    changes.append({'severity': 'medium', 'kind': fn_def['kind'] + ' (field reference)', 'category': 'password',
                                    'location': location_of(el), 'count': 0, 'before': preview_redactions(current_txt),
                                    'note': 'This call reads its value from field ' + value_arg + ' \u2014 nothing to redact here, but reviewers should know where it comes from'})
                return current_txt

            pos = 0
            while True:
                m = fn_name_re.search(txt, pos)
                if not m: break
                pos = m.end()
                fn_def = next((f for f in native_cred_fns if f['name'].lower() == m.group(1).lower()), None)
                if not fn_def: continue
                # Walk to the matching close paren, string-aware, same as the MBS pass.
                i = m.end() - 1
                j = match_paren(txt, i)
                span = txt[i + 1:j - 1]
                args = split_top_level_args(span)
                before = txt

                if fn_def['keyIdx'] >= 0:
                    # Crypt family: fixed key position.
                    if len(args) > fn_def['keyIdx']: txt = handle_arg(args[fn_def['keyIdx']], fn_def, fn_def['name'], i, j, txt)
                else:
                    # JSONSetElement: gather key/value pairs from the flat
                    # form or from each bracketed [key;value;type] group,
                    # then treat a value like a secret when its key name
                    # matches the credential keyword list.
                    pairs = []
                    if len(args) >= 2 and args[1].startswith('['):
                        # splitTopLevelArgs tracks parens and strings but not
                        # square brackets, so each [key;value;type] group
                        # arrives shredded across several args. Re-join from
                        # the arg that opens a bracket to the arg that closes
                        # it, then split the inside.
                        g = 1
                        while g < len(args):
                            if not args[g].startswith('['):
                                g += 1
                                continue
                            grp = args[g]
                            g2 = g
                            while not grp.endswith(']') and g2 + 1 < len(args):
                                g2 += 1
                                grp += ';' + args[g2]
                            if grp.startswith('[') and grp.endswith(']'):
                                triple = split_top_level_args(grp[1:-1])
                                if len(triple) >= 2: pairs.append((triple[0], triple[1]))
                            g = g2 + 1
                    elif len(args) >= 3:
                        pairs.append((args[1], args[2]))
                    # The call's close-paren position shifts as literals are
                    # replaced, so the end bound is re-based after each
                    # redaction; otherwise a later pair in the same call
                    # could be skipped by a stale bound.
                    cur_end = j
                    for key_expr, val_expr in pairs:
                        if not cred_name_re or not is_bare_string(key_expr): continue
                        if not cred_name_re.search(key_expr[1:-1]): continue
                        prev_len = len(txt)
                        txt = handle_arg(val_expr, fn_def, 'JSONSetElement key ' + key_expr, i, cur_end, txt)
                        cur_end += len(txt) - prev_len
                # If the text was mutated the call span may have shifted;
                # continue scanning from the original call's opening paren.
                if txt != before: pos = i

        for el in calcs:
            if el not in done: process_native_creds(el)
        for el in custom_fns:
            if el not in done: process_native_creds(el)

    # 2 + 3 + 6: known keys, inline keyword=literal, URLs/IPs across all calcs + custom functions
    for el in calcs: process_calc_el(el, None)
    for el in custom_fns: process_calc_el(el, 'Custom function body')

    # 4: <Text> nodes carrying a known key format
    if cfg['textnode'] and known_key_re:
        for t in [e for e in all_els if e.tagName == 'Text' and has_ancestor(e, 'Step')]:
            txt = text_content(t)
            if not js_trim(txt) or not known_key_re.search(txt): continue
            set_text_content(t, '[REDACTED]', doc); tally1('api_key', 1)
            changes.append({'severity': 'medium', 'kind': 'Text node (key format)', 'category': 'api_key', 'location': location_of(t), 'count': 1, 'before': '[REDACTED]', 'note': 'Key-format string in a step Text element'})

    # 5: connection-string attributes with an embedded credential. Covers
    # password=/pwd=, Azure AccountKey= and SAS, generic AccessToken= and
    # AuthenticationToken=, plus jdbc:mysql://user:password@host style URL
    # passwords in DSN and url attributes. The key name is preserved so the
    # redacted string still reads as a connection string.
    if cfg['connstr']:
        for sel in ['ExternalDataSource', 'DataSource', 'ODBCDataSource']:
            for ds in [e for e in all_els if e.tagName == sel]:
                for an in ['DSN', 'ConnectionString', 'connection', 'connectionString', 'url', 'Url']:
                    val = ds.getAttribute(an)
                    if not val: continue
                    hit = [False]
                    rv = val
                    if _CONN_KEY_RE.search(rv):
                        rv = _CONN_KEY_SUB_RE.sub(lambda m: m.group(1) + m.group(2) + '[REDACTED]', rv)
                        hit[0] = True
                    if _CONN_USERINFO_RE.search(rv):
                        def userinfo(m):
                            if m.group(3) == '[REDACTED]': return m.group(0)
                            hit[0] = True
                            return m.group(1) + m.group(2) + ':[REDACTED]@'
                        rv = _CONN_USERINFO_RE.sub(userinfo, rv)
                    if hit[0] and rv != val:
                        ds.setAttribute(an, rv)
                        tally1('password', 1)
                        changes.append({'severity': 'medium', 'kind': 'Connection string credential', 'category': 'password', 'location': ds.tagName + nm(ds), 'count': 1, 'before': preview_redactions(rv), 'note': 'Attribute "' + an + '" contained an embedded credential'})

    # 7: attributes whose NAME looks like a credential
    if cred_name_re:
        for el in all_els:
            for attr_name, val in attr_items(el):
                if not cred_name_re.search(attr_name): continue
                val = val or ''
                if len(val) < 6 or val == '[REDACTED]' or _REDACTED_ANY_RE.search(val): continue
                cat = categ_from_name(attr_name)
                el.setAttribute(attr_name, '[REDACTED]'); tally1(cat, 1)
                changes.append({'severity': 'medium', 'kind': 'Attribute (credential name)', 'category': cat, 'location': el.tagName + nm(el), 'count': 1, 'before': attr_name + '="[REDACTED]"', 'note': 'Attribute name matches a credential keyword'})

    # 8: comment audit, FLAG ONLY. The keyword passes deliberately skip
    # comments so documentation isn't mangled, which created one leak class:
    # plain-English credentials ("temp password is hunter2") written into a
    # script comment or a field comment. Redacting prose is too destructive,
    # so a finding is raised for manual review and nothing is modified. The
    # keyword must be followed within a short window by "is", ":" or "=" and
    # a value-like token, so "set the API key in preferences" stays quiet.
    if cfg['commentaudit'] and cred_name_re:
        comment_leak_re = jsre('(?:' + '|'.join(cfg['cred_name_kws']) + r')[^\r\n]{0,30}?(?:\bis\b|[:=])[ \t]*\S{3,}', re.I)

        def audit_comment_text(txt, where_kind, loc_el):
            for kind, sp_text in split_comments(txt):
                if kind != 'comment': continue
                if not comment_leak_re.search(sp_text): continue
                changes.append({'severity': 'medium', 'kind': where_kind, 'category': 'credential', 'location': location_of(loc_el), 'count': 0, 'before': excerpt(sp_text), 'note': 'A comment mentions a credential next to a value \u2014 nothing was changed, review by hand before sharing'})
        for el in calcs: audit_comment_text(text_content(el), 'Comment mentions a credential', el)
        for el in custom_fns: audit_comment_text(text_content(el), 'Comment mentions a credential (custom function)', el)
        # DDR field comments live in <Comment> elements or comment attributes.
        for el in [e for e in all_els if e.tagName == 'Comment']:
            t = text_content(el)
            if comment_leak_re.search(t): changes.append({'severity': 'medium', 'kind': 'Field comment mentions a credential', 'category': 'credential', 'location': location_of(el), 'count': 0, 'before': excerpt(t), 'note': 'Nothing was changed \u2014 review by hand before sharing'})

    # 9: optional PII pass, OFF by default. Value lists, ExecuteSQL literals
    # and DDR exports routinely carry real email addresses and, occasionally,
    # card numbers. Emails are shape-matched; digit runs of 13 to 19 are only
    # treated as cards when they pass the Luhn check, which keeps FileMaker's
    # own long internal ids out of the findings. Runs across every text node,
    # CDATA section and attribute in the document, because personal data is
    # not confined to calculations the way credentials are.
    if cfg['piiemail'] or cfg['piicard']:
        # No lookbehind: Safari before 16.4 throws on lookbehind at compile
        # time, which would kill the whole scan. The leading context char is
        # captured and re-emitted instead.
        def luhn_ok(digits):
            total, dbl = 0, False
            for ch in reversed(digits):
                d = ord(ch) - 48
                if dbl:
                    d *= 2
                    if d > 9: d -= 9
                total += d
                dbl = not dbl
            return total % 10 == 0

        def redact_pii(s):
            n = [0]
            cs = []
            if cfg['piiemail']:
                def email(m):
                    if m.group(0) == '[EMAIL]': return m.group(0)
                    n[0] += 1; cs.append('pii')
                    return '[EMAIL]'
                s = _EMAIL_RE.sub(email, s)
            if cfg['piicard']:
                def card(m):
                    digits = _CARD_SEP_RE.sub('', m.group(2))
                    if len(digits) < 13 or len(digits) > 19 or not luhn_ok(digits): return m.group(0)
                    n[0] += 1; cs.append('pii')
                    return m.group(1) + '[CARD]'
                s = _CARD_RE.sub(card, s)
            return {'text': s, 'count': n[0], 'cats': cs}
        # Text and CDATA nodes across the whole document. Writing nodeValue
        # preserves the node type, so calculations stay inside their CDATA.
        for t_node in list(text_nodes(root)):
            val = t_node.data or ''
            if not js_trim(val): continue
            rp = redact_pii(val)
            if rp['count'] > 0:
                t_node.data = rp['text']; tally1('pii', rp['count'])
                changes.append({'severity': 'medium', 'kind': 'Personal data', 'category': 'pii', 'location': location_of(t_node.parentNode or root), 'count': rp['count'], 'before': preview_redactions(rp['text']), 'note': 'Email address or card number redacted'})
        for el in all_els:
            for attr_name, val in attr_items(el):
                rp = redact_pii(val or '')
                if rp['count'] > 0:
                    el.setAttribute(attr_name, rp['text']); tally1('pii', rp['count'])
                    changes.append({'severity': 'medium', 'kind': 'Personal data (attribute)', 'category': 'pii', 'location': el.tagName + nm(el), 'count': rp['count'], 'before': preview_redactions(rp['text']), 'note': 'Email address or card number in attribute "' + attr_name + '"'})

    return {'clone': doc, 'changes': changes, 'tally': tally, 'anyChange': tally['total'] > 0}


# ── CDATA REPAIR (ported from Clockwork Inspector) ───────────
# FileMaker exports sometimes contain broken CDATA boundaries: a literal
# ]]> inside calc content, or an unclosed CDATA. Four escalating passes,
# stopping as soon as DOMParser accepts the file.

# Pass 1: escape ]]> not followed (after whitespace) by < (a tag start).
def repair_filemaker_cdata(inp):
    out, pos, n, escaped_count = [], 0, len(inp), 0
    while pos < n:
        idx = inp.find(']]>', pos)
        if idx == -1:
            out.append(inp[pos:])
            break
        out.append(inp[pos:idx])
        look = idx + 3
        while look < n and inp[look] in ' \t\n\r':
            look += 1
        if look < n and inp[look] == '<':
            out.append(']]>')
        else:
            out.append(']]]]><![CDATA[>')
            escaped_count += 1
        pos = idx + 3
    return {'text': ''.join(out), 'escapedCount': escaped_count}


# Pass 2: insert synthetic ]]> before a nested <![CDATA[ opening.
def repair_unclosed_cdata(inp):
    out, pos, n, fixed_count = [], 0, len(inp), 0
    OPEN, CLOSE = '<![CDATA[', ']]>'
    while pos < n:
        open_idx = inp.find(OPEN, pos)
        if open_idx == -1:
            out.append(inp[pos:])
            break
        out.append(inp[pos:open_idx + len(OPEN)])
        cs = open_idx + len(OPEN)
        next_open, next_close = inp.find(OPEN, cs), inp.find(CLOSE, cs)
        if next_close != -1 and (next_open == -1 or next_close < next_open):
            out.append(inp[cs:next_close + len(CLOSE)])
            pos = next_close + len(CLOSE)
        elif next_open != -1:
            out.append(inp[cs:next_open]); out.append(CLOSE); fixed_count += 1; pos = next_open
        else:
            out.append(inp[cs:]); out.append(CLOSE); fixed_count += 1; pos = n
    return {'text': ''.join(out), 'fixedCount': fixed_count}


# Pass 3: use the parser's reported line/column to inject ]]> before the next </.
def repair_at_line_col(inp, line, col):
    offset, cur_line = 0, 1
    while cur_line < line and offset < len(inp):
        nl = inp.find('\n', offset)
        if nl == -1:
            offset = len(inp)
            break
        offset = nl + 1
        cur_line += 1
    offset = min(len(inp), offset + max(0, col - 1))
    cdata_start = inp.rfind('<![CDATA[', 0, offset + 9)
    if cdata_start == -1: return None
    next_close = inp.find('</', cdata_start + 9)
    if next_close == -1: return None
    return {'text': inp[:next_close] + ']]>' + inp[next_close:], 'fixed': True}


_CTRL_RE = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]')


# Pass 4 (last resort): strip every CDATA wrapper and entity-encode content.
def strip_cdata_wrappers(inp):
    out, pos, n, stripped_count = [], 0, len(inp), 0
    OPEN, CLOSE = '<![CDATA[', ']]>'

    def esc(s):
        return _CTRL_RE.sub('\ufffd', s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    while pos < n:
        oi = inp.find(OPEN, pos)
        if oi == -1:
            out.append(inp[pos:])
            break
        out.append(inp[pos:oi])
        cs = oi + len(OPEN)
        next_open = inp.find(OPEN, cs)
        search_end = n if next_open == -1 else next_open
        last_close = inp.rfind(CLOSE, 0, search_end + len(CLOSE))
        if last_close == -1 or last_close < cs:
            content_end = search_end
            pos = search_end
        else:
            content_end = last_close
            pos = last_close + len(CLOSE)
        out.append(esc(inp[cs:content_end]))
        stripped_count += 1
    return {'text': ''.join(out), 'strippedCount': stripped_count}


# ── FILE HANDLING ────────────────────────────────────────────
class ScrubError(Exception):
    pass


_ENC_DECL_RE = jsre(r'''^(<\?xml\b[^?]*?)\s+encoding\s*=\s*(?:"[^"]*"|'[^']*')''', re.I)


def _decode(data):
    if data.startswith(b'\xef\xbb\xbf'): return data[3:].decode('utf-8', 'replace')
    if data.startswith(b'\xff\xfe'): return data[2:].decode('utf-16-le', 'replace')
    if data.startswith(b'\xfe\xff'): return data[2:].decode('utf-16-be', 'replace')
    return data.decode('utf-8', 'replace')


def _parse(text):
    try:
        return expatbuilder.parseString(text, namespaces=False), None
    except ExpatError as e:
        return None, e


def load_file(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError:
        raise ScrubError('Could not read the file')
    text = _decode(data)
    if text[:1] == '\ufeff': text = text[1:]
    text = _ENC_DECL_RE.sub(lambda m: m.group(1), text, count=1)

    candidate = text
    doc, pe = _parse(candidate)

    # Multi-pass CDATA repair on any parse error. The passes are fast and
    # do nothing if there are no broken CDATA boundaries to fix.
    if pe:
        # Pass 1
        p1 = repair_filemaker_cdata(candidate)
        if p1['escapedCount'] > 0:
            candidate = p1['text']; doc, pe = _parse(candidate)
        # Pass 2
        if pe:
            p2 = repair_unclosed_cdata(candidate)
            if p2['fixedCount'] > 0:
                candidate = p2['text']; doc, pe = _parse(candidate)
        # Pass 3: up to 50 attempts using error line/col
        att = 0
        while att < 50 and pe:
            fix = repair_at_line_col(candidate, pe.lineno, pe.offset + 1)
            if not fix or not fix['fixed']: break
            candidate = fix['text']; doc, pe = _parse(candidate)
            att += 1
        # Pass 4: nuclear, strip all CDATA wrappers
        if pe:
            p4 = strip_cdata_wrappers(text)
            if p4['strippedCount'] > 0:
                candidate = p4['text']; doc, pe = _parse(candidate)

    if pe:
        detail = js_trim(_WS_RUN.sub(' ', str(pe)))
        if len(detail) > 200: detail = detail[:200]
        raise ScrubError('XML parse error: ' + detail)
    return {'rawText': candidate, 'fileName': os.path.basename(path), 'doc': doc, 'size': len(data)}


# ── SETTINGS PANEL ───────────────────────────────────────────
SETTINGS = [
    ('Known API key formats', [
        ('skkey', 'sk- / sk-proj-', 'OpenAI keys', True),
        ('aikey', 'AIza...', 'Google AI keys', True),
        ('xaikey', 'xai- / gsk_', 'xAI / Groq keys', True),
        ('awskey', 'AKIA / ASIA', 'AWS access keys', True),
        ('ghkey', 'ghp_ / github_pat_', 'GitHub tokens', True),
        ('slackkey', 'xoxb- / xoxp-', 'Slack tokens', True),
        ('stripekey', 'sk_live_ / sk_test_', 'Stripe live + test keys', True),
        ('sgkey', 'SG.xxxx.xxxx', 'SendGrid API keys', True),
        ('ottokey', 'dk_ / ak_', 'OttoFMS Data / Admin API keys', True),
        ('jwtkey', 'eyJ...\u200a.\u200aeyJ...', 'JWT / JWS tokens', True),
        ('pemkey', 'BEGIN PRIVATE KEY', 'PEM / SSH private keys', True),
        ('webhook', 'hooks.slack.com / ...', 'Slack / Discord / Teams webhooks', True),
    ]),
    ('Variable / attribute names', [
        ('apikey', 'api_key / apikey', 'REST API keys', True),
        ('token', 'token / bearer', 'Auth tokens, JWTs', True),
        ('password', 'password / passwd', 'Passwords', True),
        ('secret', 'secret', 'OAuth secrets, HMAC keys', True),
        ('smtp', 'smtp_pass / smtp_key', 'Mail credentials', True),
        ('privatekey', 'private_key / auth_key', 'Private / signing keys', True),
        ('credential', 'credential / oauth', 'OAuth credentials', True),
    ]),
    ('Inline patterns', [
        ('inline', 'keyword = "value"', 'Assigned literals', True),
        ('connstr', 'password= / AccountKey=', 'Connection strings, Azure keys', True),
        ('plugin', 'MBS("Register") / *_Register', 'Plugin licence keys', True),
        ('curlcred', 'CURL.SetOptionPassword / etc', 'SFTP/CURL credentials, traced to source', True),
        ('headercred', 'Authorization: / Cookie: / -u', 'HTTP header and cURL option credentials', True),
        ('urlsecret', '?api_key= / user:pass@', 'URL query secrets and URL passwords', True),
        ('urlhost', 'https://hostname/...', 'Internal URLs \u2192 https://[HOST]/...', True),
        ('textnode', '<Text> nodes', 'Raw string parameters in steps', True),
        ('jsoncred', '"keyword":"value"', 'JSON body credentials', True),
        ('nativecred', 'JSONSetElement / Crypt*', 'Positional key arguments, traced to source', True),
        ('credtarget', '<Password> / Set Field', 'Re-Login, Add Account, SMTP, credential fields', True),
        ('b64', 'base64 user:pass', 'Decoded Basic-auth literals', True),
        ('commentaudit', 'comment audit', 'Flags credentials in comments, changes nothing', True),
    ]),
    ('Personal data (off by default)', [
        ('piiemail', 'email addresses', '\u2192 [EMAIL], everywhere in the file', False),
        ('piicard', 'card numbers', '\u2192 [CARD], Luhn checked', False),
    ]),
]
SETTING_IDS = [s[0] for _, rows in SETTINGS for s in rows]


def default_checked():
    return {s[0]: s[3] for _, rows in SETTINGS for s in rows}


# ── CUSTOM PATTERNS ──────────────────────────────────────────
def add_custom_pattern(custom_kws, val):
    val = js_trim((val or '')[:60])
    if val and val not in custom_kws:
        custom_kws.append(val)


def remove_custom_pattern(custom_kws, kw):
    custom_kws[:] = [k for k in custom_kws if k != kw]


# ── CONFIG FROM UI ───────────────────────────────────────────
def build_config(checked, custom_kws):
    known = {
        'sk': checked['skkey'], 'aiza': checked['aikey'],
        'xai': checked['xaikey'], 'groq': checked['xaikey'],
        'aws': checked['awskey'], 'github': checked['ghkey'],
        'slack': checked['slackkey'], 'stripe': checked['stripekey'],
        'sendgrid': checked['sgkey'], 'otto': checked['ottokey'],
        'pem': checked['pemkey'], 'webhook': checked['webhook'],
        'jwt': checked['jwtkey'],
    }
    active = {
        'apikey': checked['apikey'], 'token': checked['token'],
        'password': checked['password'], 'secret': checked['secret'],
        'smtp': checked['smtp'], 'privatekey': checked['privatekey'],
        'credential': checked['credential'], 'custom': list(custom_kws),
    }
    return {
        'known_key_re': build_known_key_re(known),
        'kw_parts': kw_parts_from(active),
        'cred_name_kws': kw_parts_from(active),
        'inline': checked['inline'], 'url': checked['urlhost'],
        'textnode': checked['textnode'], 'connstr': checked['connstr'],
        'plugin': checked['plugin'], 'azure': checked['connstr'],
        'pem': checked['pemkey'], 'curlcred': checked['curlcred'],
        'headercred': checked['headercred'], 'urlsecret': checked['urlsecret'],
        'jsoncred': checked['jsoncred'], 'nativecred': checked['nativecred'],
        'credtarget': checked['credtarget'], 'b64': checked['b64'],
        'commentaudit': checked['commentaudit'],
        'piiemail': checked['piiemail'], 'piicard': checked['piicard'],
    }


# ── SERIALISE OUTPUT ─────────────────────────────────────────
# No changes -> hand back the original bytes untouched.
# Otherwise serialise the clone (CDATA preserved) with a native-style declaration.
def _cdata_writexml(self, writer, indent='', addindent='', newl=''):
    writer.write('<![CDATA[%s]]>' % self.data.replace(']]>', ']]]]><![CDATA[>'))


minidom.CDATASection.writexml = _cdata_writexml

_MINIDOM_DECL = '<?xml version="1.0" ?>'
_DECL_RE = jsre(r'^<\?xml[^?]*\?>\s*', re.I)


def serialize_output(state):
    last_run = state.get('lastRun')
    if not last_run: return None
    if not last_run['anyChange']: return state['rawText']
    x = last_run['clone'].toxml()
    if x.startswith(_MINIDOM_DECL): x = x[len(_MINIDOM_DECL):]
    x = _DECL_RE.sub('', x, count=1)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + x


# ── RENDER FINDINGS ──────────────────────────────────────────
CAT_NAMES = {'api_key': 'API keys', 'token': 'Auth tokens', 'password': 'Passwords', 'secret': 'Secrets', 'smtp': 'SMTP credentials', 'oauth': 'OAuth tokens', 'credential': 'Credentials', 'license': 'Plugin licence keys', 'url': 'Hostnames and IPs', 'pii': 'Personal data'}


def render_findings(state):
    findings = state['findings']
    if not findings:
        print('No credential values found')
        print('Nothing matched the active patterns. Account names, file paths and hostnames are not checked.')
        return
    high = sum(1 for f in findings if f['severity'] == 'high')
    medium = sum(1 for f in findings if f['severity'] == 'medium')
    redacted = state['lastRun']['tally']['total']
    print('High %d   Medium %d   Values %d' % (high, medium, redacted))
    print('Values below are redacted automatically. A few are flagged for manual review instead, where nothing in this file can be safely redacted \u2014 see the note under each')
    for f in findings:
        cnt = ' (' + str(f['count']) + ' values)' if f['count'] and f['count'] > 1 else ''
        loc = '  ' + f['location'] if f['location'] else ''
        print()
        print('[' + f['severity'] + '] ' + f['kind'] + cnt + loc)
        for line in f['before'].split('\n'):
            print('    ' + line)
        print('    ' + f['note'])
    print()
    print('%d finding%s, %d value%s redacted' % (len(findings), '' if len(findings) == 1 else 's', redacted, '' if redacted == 1 else 's'))


# ── SUMMARY OVERLAY ──────────────────────────────────────────
def show_summary(s):
    t = s['tally']
    if s['anyChange']:
        print('%d value%s redacted \u2014 %s written' % (t['total'], '' if t['total'] == 1 else 's', s['outName']))
    elif s['untouched']:
        print('No changes \u2014 original left untouched')
    else:
        print('No changes \u2014 original file saved as ' + s['outName'])
    print('By category')
    rows = [(CAT_NAMES[c], t.get(c, 0)) for c in CAT_NAMES if t.get(c, 0)]
    if not rows:
        print('  No values redacted')
    for name, n in rows:
        print('  %-22s %d' % (name, n))
    print('Line count')
    print('  Original %s   Redacted %s%s' % (format(s['origLines'], ','), format(s['redLines'], ','), '   Line count preserved' if s['origLines'] == s['redLines'] else ''))
    print('Hostnames and IPs are replaced with [HOST], not [REDACTED]. Pattern matching is heuristic and does not cover account names, file paths or arbitrary data. Review before sharing.')


# ── RUN (redact-first; findings derived from the redacted clone) ──
def run_file(path, cfg, suffix, overwrite, quiet=False):
    state = load_file(path)
    meta = format(round(len(state['rawText']) / 1024), ',') + ' KB  \u00b7  ' + format(state['rawText'].count('\n') + 1, ',') + ' lines'
    if state['size'] > 20 * 1024 * 1024: meta += '  \u00b7  large file, processing may be slow'
    if not quiet: print(meta)
    state['lastRun'] = redact_document(state['doc'], cfg)
    state['findings'] = state['lastRun']['changes']
    if not quiet: render_findings(state)

    out = serialize_output(state)
    any_change = state['lastRun']['anyChange']
    if overwrite:
        out_path = path
    else:
        base_name = re.sub(r'\.xml\Z', '', state['fileName'] or 'export.xml', flags=re.I)
        out_path = os.path.join(os.path.dirname(path), base_name + suffix + '.xml')
    untouched = overwrite and not any_change
    if not untouched:
        with open(out_path, 'w', encoding='utf-8', newline='') as f:
            f.write(out)
    if not quiet:
        print()
        show_summary({'tally': state['lastRun']['tally'], 'origLines': state['rawText'].count('\n') + 1, 'redLines': out.count('\n') + 1,
                      'outName': os.path.basename(out_path), 'anyChange': any_change, 'untouched': untouched})
    return state['lastRun']['tally']['total']


# ── CLI ──────────────────────────────────────────────────────
def list_patterns(checked):
    n = 0
    for group, rows in SETTINGS:
        print(group)
        for sid, name, desc, _ in rows:
            n += 1
            print('  %2d [%s] %-13s %-32s %s' % (n, 'x' if checked[sid] else ' ', sid, name, desc))


def interactive_settings(checked, custom_kws):
    while True:
        list_patterns(checked)
        print('Custom keywords')
        print('  ' + (', '.join(custom_kws) if custom_kws else '(none)'))
        try:
            line = input('Toggle numbers, +keyword to add, -keyword to remove, Enter to finish: ')
        except EOFError:
            print()
            return
        if not line.strip():
            return
        try:
            tokens = shlex.split(line)
        except ValueError:
            tokens = line.split()
        for tok in tokens:
            if tok.startswith('+'):
                add_custom_pattern(custom_kws, tok[1:])
            elif tok.startswith('-') and len(tok) > 1:
                remove_custom_pattern(custom_kws, js_trim(tok[1:]))
            elif tok.isdigit() and 1 <= int(tok) <= len(SETTING_IDS):
                sid = SETTING_IDS[int(tok) - 1]
                checked[sid] = not checked[sid]
            else:
                print('Ignored: ' + tok)
        print()


def expand_files(patterns, suffix, overwrite):
    files, seen, missing = [], set(), []
    skip_tail = (suffix + '.xml').lower()
    for pat in patterns:
        if os.path.exists(pat) or not any(c in pat for c in '*?['):
            matches, from_glob = [pat], False
        else:
            matches, from_glob = sorted(glob.glob(pat)), True
        matches = [m for m in matches if os.path.isfile(m)]
        if from_glob and not overwrite:
            matches = [m for m in matches if not m.lower().endswith(skip_tail)]
        if not matches:
            print('No file matches ' + pat, file=sys.stderr)
            missing.append(pat)
        for m in matches:
            key = os.path.abspath(m)
            if key not in seen:
                seen.add(key)
                files.append(m)
    return files, missing


def main(argv=None):
    if sys.version_info < (3, 13):
        print('Python 3.13 or later is required', file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(description='Strip credential values from FileMaker XML exports. Everything runs locally.')
    parser.add_argument('files', nargs='*', metavar='FILE_OR_PATTERN', help='XML files or wildcard patterns such as *.xml or abc_*.xml')
    out_group = parser.add_mutually_exclusive_group()
    out_group.add_argument('--suffix', help='suffix added to the output file name (default: -redacted)')
    out_group.add_argument('--overwrite', action='store_true', help='write the redacted XML back over the original files')
    parser.add_argument('--enable', dest='toggles', action='append', type=lambda v: (True, v), default=[], metavar='ID', help='turn a detection pattern on (repeatable)')
    parser.add_argument('--disable', dest='toggles', action='append', type=lambda v: (False, v), metavar='ID', help='turn a detection pattern off (repeatable)')
    parser.add_argument('--keyword', action='append', default=[], metavar='KW', help='add a custom keyword (repeatable)')
    parser.add_argument('--list-patterns', action='store_true', help='list pattern ids and their defaults, then exit')
    parser.add_argument('-q', '--quiet', '--silent', dest='quiet', action='store_true', help='print nothing except errors; check the exit code')
    parser.add_argument('-i', '--interactive', action='store_true', help='toggle patterns and keywords in a menu before scanning')
    raw = list(sys.argv[1:] if argv is None else argv)
    joined = []
    while raw:
        tok = raw.pop(0)
        if tok == '--suffix' and raw:
            tok = '--suffix=' + raw.pop(0)
        joined.append(tok)
    args = parser.parse_args(joined)

    checked = default_checked()
    custom_kws = []
    for state, sid in args.toggles:
        if sid not in checked:
            parser.error('unknown pattern id "%s" (valid: %s)' % (sid, ', '.join(SETTING_IDS)))
        checked[sid] = state
    for kw in args.keyword:
        add_custom_pattern(custom_kws, kw)

    if args.list_patterns:
        list_patterns(checked)
        return 0
    if not args.files:
        parser.error('at least one FILE_OR_PATTERN is required')
    if args.suffix == '':
        parser.error('--suffix cannot be empty; use --overwrite to replace the originals')
    suffix = '-redacted' if args.suffix is None else args.suffix
    if args.interactive:
        if not sys.stdin.isatty():
            parser.error('--interactive needs a terminal')
        interactive_settings(checked, custom_kws)

    files, missing = expand_files(args.files, suffix, args.overwrite)
    cfg = build_config(checked, custom_kws)
    failed, with_redactions, total = [], 0, 0
    for path in files:
        if not args.quiet: print('\u2500\u2500 ' + path + ' \u2500\u2500')
        try:
            n = run_file(path, cfg, suffix, args.overwrite, args.quiet)
        except ScrubError as e:
            print(path + ': ' + str(e), file=sys.stderr)
            failed.append(path)
        else:
            total += n
            if n: with_redactions += 1
        if not args.quiet: print()
    if len(files) > 1 and not args.quiet:
        print('%d files processed, %d with redactions, %d values redacted, %d failed' % (len(files) - len(failed), with_redactions, total, len(failed)))
        for path in failed:
            print('  failed: ' + path)
    return 1 if failed or missing else 0


if __name__ == '__main__':
    sys.exit(main())
