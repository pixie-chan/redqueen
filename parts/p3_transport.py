

class BudgetExceeded(Exception):
    pass


class OutOfScope(Exception):
    pass


class Resp:
    def __init__(self, status, headers, body, url, redirects, elapsed):
        self.status = status
        self.headers = headers          # lowercased dict
        self.body = body                # bytes
        self.url = url
        self.redirects = redirects
        self.elapsed = elapsed

    @property
    def text(self):
        try:
            return self.body.decode("utf-8", "replace")
        except Exception:
            return ""

    def header(self, name):
        return self.headers.get(name.lower(), "")

    @property
    def set_cookies(self):
        raw = self.headers.get("set-cookie-list", [])
        return raw if isinstance(raw, list) else []


class Throttle:
    def __init__(self, rps):
        self.rps = max(0.2, float(rps))
        self.next = 0.0
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            now = time.monotonic()
            if now < self.next:
                delay = self.next - now
            else:
                delay = 0.0
            jitter = random.uniform(0.9, 1.15)
            self.next = max(time.monotonic(), self.next) + jitter / self.rps
        if delay > 0:
            time.sleep(delay)


class Transport:
    def __init__(self, target, allow, rps, max_requests, timeout, insecure, local):
        p = urllib.parse.urlsplit(target)
        if p.scheme not in ("http", "https"):
            raise SystemExit("target must be http:// or https://")
        self.scheme = p.scheme
        self.host = p.hostname or ""
        self.port = p.port or (443 if p.scheme == "https" else 80)
        self.base = f"{self.scheme}://{self.host}:{self.port}"
        self.path = p.path or "/"
        self.allow = set(a.strip().lower() for a in allow if a.strip())
        self.allow.add(self.host.lower())
        try:
            ipaddress.ip_address(self.host)
            is_ip = True
        except ValueError:
            is_ip = False
        if not is_ip:
            if self.host.startswith("www."):
                self.allow.add(self.host[4:])
            else:
                self.allow.add("www." + self.host)
        self.local = local
        self.throttle = Throttle(rps)
        self.max_requests = max_requests
        self.used = 0
        self.timeout = timeout
        self.insecure = insecure
        self.rate_limited = 0
        self.notes = []
        self.lock = threading.Lock()
        self.frozen = False
        if not local:
            try:
                ipaddress.ip_address(self.host)
                raise SystemExit(
                    "IP-literal targets are refused. Use a hostname and "
                    "--allow, or --local for 127.0.0.1 testing.")
            except ValueError:
                pass

    def in_scope(self, url):
        p = urllib.parse.urlsplit(url)
        if p.scheme not in ("http", "https"):
            return False
        host = (p.hostname or "").lower()
        if host in ("127.0.0.1", "localhost", "::1") and self.local:
            return True
        for a in self.allow:
            if host == a or (a.startswith(".") and host.endswith(a)) or \
               (a.startswith("*.") and host.endswith(a[1:])):
                return True
        return False

    def _conn(self, scheme, host, port):
        if scheme == "https":
            ctx = ssl.create_default_context()
            if self.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection(host, port, timeout=self.timeout,
                                               context=ctx)
        return http.client.HTTPConnection(host, port, timeout=self.timeout)

    def _budget(self):
        # A frozen transport is the Tier C guarantee: once the dossier phase
        # starts, no code path can put bytes on the wire. Checked here, the
        # single choke point every request passes through.
        if getattr(self, "frozen", False):
            raise OutOfScope("transport is frozen (tierc research phase)")
        with self.lock:
            if self.used >= self.max_requests:
                raise BudgetExceeded(
                    f"budget of {self.max_requests} requests reached")
            self.used += 1
        self.throttle.wait()

    def request_external(self, url, cap=1_500_000, timeout=30.0):
        """GET-only passive public source (wayback/crt.sh). Throttled,
        budgeted, never reachable from attack paths, scope-checked to the
        two allowlisted provider hosts by the caller. One retry: public
        archive APIs flake."""
        p = urllib.parse.urlsplit(url)
        if p.scheme not in ("http", "https"):
            raise OutOfScope(url)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        last = None
        for attempt in range(2):
            self._budget()
            conn = self._conn(p.scheme, p.hostname,
                              p.port or (443 if p.scheme == "https" else 80))
            conn.timeout = timeout
            try:
                conn.request("GET", path,
                             headers={"User-Agent": UA, "Accept": "*/*"})
                r = conn.getresponse()
                data = r.read(cap)
                if r.status == 200:
                    return r.status, data
                last = RuntimeError(f"HTTP {r.status}")
            except (OSError, http.client.HTTPException) as e:
                last = e
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            if attempt == 0:
                time.sleep(1.5)
        raise last if last else RuntimeError("external source failed")

    def request(self, method, url, headers=None, body=None, follow=True):
        if not self.in_scope(url):
            raise OutOfScope(url)
        self._budget()
        hdrs = {"User-Agent": UA, "Accept": "*/*", "Accept-Language": "en"}
        if headers:
            hdrs.update(headers)
        redirects = []
        current, current_body = url, body
        for _ in range(6):
            p = urllib.parse.urlsplit(current)
            path = p.path or "/"
            if p.query:
                path += "?" + p.query
            t0 = time.monotonic()
            err = None
            for attempt in range(2):
                conn = self._conn(p.scheme, p.hostname, p.port)
                try:
                    conn.request(method, path, body=current_body, headers=hdrs)
                    r = conn.getresponse()
                    data = r.read(2_000_000)
                    err = None
                    break
                except (OSError, http.client.HTTPException) as e:
                    err = e
                    r, data = None, None
                    if attempt == 0:
                        time.sleep(0.35)
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
            if err is not None:
                raise RuntimeError(f"{type(err).__name__}: {err}")
            elapsed = time.monotonic() - t0
            rh = {}
            for k, v in r.getheaders():
                kl = k.lower()
                if kl == "set-cookie":
                    rh.setdefault("set-cookie-list", []).append(v)
                elif kl in rh:
                    rh[kl] = rh[kl] + ", " + v
                else:
                    rh[kl] = v
            resp = Resp(r.status, rh, data, current, list(redirects), elapsed)
            if r.status == 429:
                self.rate_limited += 1
                self.notes.append(f"429 from {current}, throttling further")
                self.throttle.rps = max(0.2, self.throttle.rps / 2)
            if follow and r.status in (301, 302, 303, 307, 308):
                loc = rh.get("location", "")
                nxt = urllib.parse.urljoin(current, loc)
                if not self.in_scope(nxt):
                    resp.headers["x-qx-out-of-scope-redirect"] = nxt
                    return resp
                redirects.append(f"{r.status} -> {nxt}")
                if r.status == 303:
                    method, current_body = "GET", None
                    hdrs.pop("Content-Length", None)
                current = nxt
                continue
            return resp
        return resp

    def _read_exact(self, fh, n):
        out = b""
        while len(out) < n:
            chunk = fh.read(n - len(out))
            if not chunk:
                break
            out += chunk
        return out

    def _read_raw_response(self, fh, sock):
        line = fh.readline(65536)
        if not line:
            return None
        parts = line.decode("iso-8859-1", "replace").rstrip("\r\n").split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            return None
        status, reason = int(parts[1]), (parts[2] if len(parts) > 2 else "")
        headers = {}
        while True:
            hl = fh.readline(65536)
            if not hl or hl in (b"\r\n", b"\n"):
                break
            k, _sep, v = hl.decode("iso-8859-1", "replace").partition(":")
            kl, v = k.strip().lower(), v.strip()
            if not kl:
                continue
            # a repeated header is joined, which is exactly how a
            # duplicated Content-Length shows up as an ambiguity
            headers[kl] = headers[kl] + ", " + v if kl in headers else v
        body = b""
        if "chunked" in headers.get("transfer-encoding", "").lower():
            chunks, size = [], 0
            for _ in range(32):            # bounded: never a chunked flood
                sz = fh.readline(65536).strip()
                if not sz:
                    break
                try:
                    size = int(sz.split(b";")[0], 16)
                except ValueError:
                    break
                if size <= 0:
                    fh.readline(65536)      # trailing CRLF, trailers dropped
                    break
                chunks.append(self._read_exact(fh, size))
                fh.readline(65536)
            body = b"".join(chunks)
        elif "content-length" in headers:
            first = headers["content-length"].split(",")[0].strip()
            if first.isdigit():
                body = self._read_exact(fh, min(int(first), 2_000_000))
        else:
            # no framing header: take what arrives, but never block on a
            # response that stays open
            try:
                sock.settimeout(0.5)
                for _ in range(32):
                    chunk = fh.read(8192)
                    if not chunk:
                        break
                    body += chunk
            except OSError:
                pass
            finally:
                sock.settimeout(self.timeout)
        return RawResp(status, headers, body, reason)

    def raw_exchange(self, url, messages, timeout=None):
        """Send pre-serialized HTTP/1.1 messages over ONE keep-alive
        connection and return the responses in order.

        Only the Tier B desync and delimiter probes use this. They need
        the exact octets on the wire: http.client computes its own
        framing and drops a duplicate Content-Length, which is precisely
        the disagreement under test. Both messages are written before
        either response is read, because a desync is only a desync if the
        follow-up is already on the wire. Scope-gated and budgeted like
        request(), one budget tick per message, never retried.
        """
        if not self.in_scope(url):
            raise OutOfScope(url)
        p = urllib.parse.urlsplit(url)
        conn = self._conn(p.scheme, p.hostname,
                          p.port or (443 if p.scheme == "https" else 80))
        conn.timeout = timeout or self.timeout
        out, fh = [], None
        try:
            sock = None
            for msg in messages:
                self._budget()          # may raise BudgetExceeded
                if sock is None:
                    conn.connect()
                    sock = conn.sock
                    sock.settimeout(timeout or self.timeout)
                    fh = sock.makefile("rb")
                sock.sendall(msg)
            if sock is not None:
                for _ in messages:
                    resp = self._read_raw_response(fh, sock)
                    if resp is None:
                        break
                    resp.url = url
                    out.append(resp)
        except (OSError, http.client.HTTPException) as e:
            if not out:                 # partial reads are still data
                raise RuntimeError(f"{type(e).__name__}: {e}")
        finally:
            if fh is not None:
                try:
                    fh.close()
                except Exception:
                    pass
            try:
                conn.close()
            except Exception:
                pass
        return out


class RawResp:
    """A response parsed straight off the socket by Transport.raw_exchange.

    Deliberately not an http.client response: the Tier B probes need the
    bytes the server actually sent, including a duplicated Content-Length,
    which http.client either refuses to hand back or normalizes away
    before we could compare it. Same field names as Resp so the tierb
    modules can treat both alike."""

    def __init__(self, status, headers, body, reason=""):
        self.status = status
        self.headers = headers          # lowercased, repeats joined with ", "
        self.body = body                # bytes
        self.reason = reason
        self.url = ""
        self.redirects = []
        self.elapsed = 0.0

    @property
    def text(self):
        try:
            return self.body.decode("utf-8", "replace")
        except Exception:
            return ""

    def header(self, name):
        return self.headers.get(name.lower(), "")

    @property
    def set_cookies(self):
        raw = self.headers.get("set-cookie-list", [])
        return raw if isinstance(raw, list) else []



    # ---------- raw HTTP/1.1 (Tier B) ----------
