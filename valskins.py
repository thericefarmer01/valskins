#!/usr/bin/env python3
"""valskins - see everyone's weapon skins the moment a Valorant match starts.

Run this on the Windows machine that Valorant is on:

    python valskins.py

Then open http://<that-pc's-lan-ip>:8787 from your Mac (or phone).

Read-only: it talks to the Riot client's own local API plus the public
valorant-api.com asset catalog. No game memory, no overlay, no writes.
"""

import argparse
import base64
import collections
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INSECURE = ssl._create_unverified_context()

# Last few requests, for the diagnostics panel. Paths only - never query strings,
# which is where the tokens live.
RECENT = collections.deque(maxlen=14)

# Details of the most recent remote 4xx, to tell an application-level refusal
# (json body with an errorCode) from an edge block (html, cloudflare headers).
LAST_REMOTE_ERROR = {}

# Riot's edge rejects obviously non-client user agents. The game sends the first
# of these; the launcher sends something like the second. Rotated on refusal.
UA_CANDIDATES = [
    "ShooterGame/{gv} Windows/10.0.19045.1.256.64bit",
    "RiotClient/{v} rso-auth (Windows;10;;Professional, x64)",
    None,   # urllib's own - what shipped up to v0.1.4
]


def deep_get(obj, key, depth=0):
    """Find a key anywhere in a nested dict. Riot reshuffles presence between
    flat and nested shapes, and this survives both."""
    if depth > 4 or not isinstance(obj, dict):
        return None
    if key in obj:
        return obj[key]
    for value in obj.values():
        found = deep_get(value, key, depth + 1)
        if found is not None:
            return found
    return None

# The client platform blob the game sends. Riot wants this exact JSON shape.
CLIENT_PLATFORM = base64.b64encode(
    (
        '{\r\n\t"platformType": "PC",\r\n\t"platformOS": "Windows",\r\n\t'
        '"platformOSVersion": "10.0.19042.1.256.64bit",\r\n\t'
        '"platformChipset": "Unknown"\r\n}'
    ).encode()
).decode()

WEAPON_ORDER = [
    "Vandal", "Phantom", "Operator", "Sheriff", "Melee", "Ghost", "Classic",
    "Spectre", "Guardian", "Odin", "Ares", "Judge", "Bucky", "Marshal",
    "Outlaw", "Bulldog", "Stinger", "Frenzy", "Shorty",
]

# Regions that share a shard with another region.
SHARD_FALLBACK = {"latam": "na", "br": "na", "na": "na", "eu": "eu",
                  "ap": "ap", "kr": "kr", "pbe": "pbe"}


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def http_json(url, method="GET", headers=None, body=None, ctx=None, timeout=15,
              insecure_retry=False):
    """Returns (status, parsed_json_or_None). Does not raise on 4xx/5xx."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    def note(status, payload=None):
        parsed = urllib.parse.urlsplit(url)
        host = parsed.netloc.split(":")[0]
        # Collapse uuids so the log stays readable and puuid-free.
        path = re.sub(r"/[0-9a-fA-F-]{30,}", "/{id}", parsed.path)
        why = ""
        if status >= 400 and isinstance(payload, dict):
            code = payload.get("errorCode") or payload.get("message")
            if code:
                why = f" [{str(code)[:60]}]"
        RECENT.append(f"{status} {method} {host}{path}{why}")

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            raw = r.read()
            note(r.status)
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            body = json.loads(raw) if raw else None
        except Exception:
            body = None
        note(e.code, body)
        if "127.0.0.1" not in url:
            LAST_REMOTE_ERROR.clear()
            LAST_REMOTE_ERROR.update({
                "status": e.code,
                "url": re.sub(r"/[0-9a-fA-F-]{30,}", "/{id}",
                              urllib.parse.urlsplit(url).path),
                "server": e.headers.get("server"),
                "content_type": e.headers.get("content-type"),
                "cf_ray": bool(e.headers.get("cf-ray")),
                # Enough of the body to tell html from json, no more.
                "body": re.sub(r"\s+", " ", raw.decode("utf-8", "replace"))[:180],
            })
        return e.code, body
    except urllib.error.URLError as e:
        # Machines with an unconfigured cert store can't verify valorant-api.com.
        # Only the public, read-only asset URLs get the insecure retry.
        if insecure_retry and isinstance(e.reason, ssl.SSLError):
            log(f"warning: TLS verify failed for {url} - retrying unverified")
            return http_json(url, method, headers, body, ctx=INSECURE, timeout=timeout)
        host = urllib.parse.urlsplit(url).netloc
        RECENT.append(f"ERR {method} {host} [{e.reason}]")
        raise NetworkError(host, e.reason) from None


def lan_ips():
    """Every private IPv4 this machine has, best guess first.

    A gaming PC routinely has ethernet plus wifi plus a VPN or Hyper-V adapter,
    and only one of them is the one the Mac can reach - so list them all rather
    than guessing. The default-route address goes first because it usually is
    the right one.
    """
    found = []

    def keep(ip):
        if not ip or ip.startswith(("127.", "169.254.")):
            return
        parts = ip.split(".")
        if len(parts) != 4 or not all(p.isdigit() for p in parts):
            return
        a, b = int(parts[0]), int(parts[1])
        if (a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)) \
                and ip not in found:
            found.append(ip)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))       # no packets sent; just picks the route
        keep(s.getsockname()[0])
    except OSError:
        pass
    finally:
        s.close()
    try:
        # Windows registers every adapter's address under the hostname.
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            keep(info[4][0])
    except (socket.gaierror, OSError):
        pass
    return found


def lan_ip():
    ips = lan_ips()
    return ips[0] if ips else "127.0.0.1"


# ---------------------------------------------------------------- riot client

class NetworkError(Exception):
    """A host couldn't be reached at all - DNS, no route, TLS refused. Worth
    distinguishing from an HTTP error, because the fix is on this machine."""

    def __init__(self, host, reason):
        self.host = host
        self.reason = reason
        dns = "getaddrinfo" in str(reason) or "11001" in str(reason)
        hint = ("DNS couldn't resolve it - check a VPN, an adblocker or a DNS "
                "filter." if dns else "Check the connection.")
        super().__init__(f"Can't reach {host}. {hint}")


class RiotAuthError(Exception):
    """Something local is wrong: no lockfile, not logged in, no session."""


class RiotApiError(Exception):
    """Riot's game servers rejected a request. Carries what they actually said,
    because 'session expired' was hiding the useful part."""

    HINTS = {
        400: "Usually a stale client version - VALORANT may have just patched.",
        401: "The token isn't accepted for game requests. Is VALORANT itself "
             "running, not just the Riot launcher?",
        403: "Riot refused the request outright. Wrong region/shard is the usual "
             "cause; try --region and --shard.",
    }

    def __init__(self, where, status, body=None):
        self.where = where
        self.status = status
        code = ""
        if isinstance(body, dict):
            code = body.get("errorCode") or body.get("message") or ""
        self.code = code
        detail = f" ({code})" if code else ""
        super().__init__(f"{where} returned HTTP {status}{detail}. "
                         f"{self.HINTS.get(status, '')}".strip())


def lockfile_path(override=None):
    if override:
        return override
    local = os.environ.get("LOCALAPPDATA", "")
    return os.path.join(local, "Riot Games", "Riot Client", "Config", "lockfile")


def shootergame_log(override=None):
    if override:
        return override
    local = os.environ.get("LOCALAPPDATA", "")
    return os.path.join(local, "VALORANT", "Saved", "Logs", "ShooterGame.log")


class Auth:
    """Local-client auth: lockfile -> entitlements token -> GLZ/PD headers."""

    def __init__(self, args):
        self.args = args
        self.port = None
        self.password = None
        self.access_token = None
        self.entitlements = None
        self.puuid = None
        self.basic = None
        self.region = args.region
        self.shard = args.shard
        self.client_version = args.client_version
        self.version_log = self.version_api = None
        self.variants = []
        self.variant = 0

    def refresh(self):
        path = lockfile_path(self.args.lockfile)
        if not os.path.exists(path):
            raise RiotAuthError(
                "Riot Client isn't running (no lockfile). Start VALORANT and try again."
            )
        with open(path, "r", encoding="utf-8") as f:
            parts = f.read().strip().split(":")
        if len(parts) < 5:
            raise RiotAuthError(f"Could not parse lockfile at {path}")
        self.port, self.password = parts[2], parts[3]

        basic = base64.b64encode(f"riot:{self.password}".encode()).decode()
        self.basic = basic
        status, data = http_json(
            f"https://127.0.0.1:{self.port}/entitlements/v1/token",
            headers={"Authorization": f"Basic {basic}"},
            ctx=INSECURE,
        )
        if status != 200 or not data or not data.get("accessToken"):
            raise RiotAuthError(
                f"Local entitlements request failed (HTTP {status}). "
                "Are you fully logged in to the Riot client?"
            )
        self.access_token = data["accessToken"]
        self.entitlements = data["token"]
        self.puuid = data["subject"]

        if not self.region or not self.shard:
            self._detect_region(basic)
        if not self.client_version:
            self._detect_client_version()
        if not self.variants:
            self.build_variants()
        return self

    def _detect_region(self, basic):
        # Preferred: the GLZ url the game itself logged.
        path = shootergame_log(self.args.log)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            m = re.search(r"https://glz-([a-z0-9-]+)-1\.([a-z0-9-]+)\.a\.pvp\.net", text)
            if m:
                self.region, self.shard = m.group(1), m.group(2)
                return
        except OSError:
            pass
        # Fallback: ask the client for its region and guess the shard.
        status, data = http_json(
            f"https://127.0.0.1:{self.port}/riotclient/region-locale",
            headers={"Authorization": f"Basic {basic}"},
            ctx=INSECURE,
        )
        if status == 200 and data:
            region = (data.get("region") or "").lower()
            if region:
                self.region = self.region or region
                self.shard = self.shard or SHARD_FALLBACK.get(region, region)
                return
        raise RiotAuthError(
            "Could not detect your region/shard. Pass them explicitly, "
            "e.g. --region na --shard na"
        )

    def _log_version(self):
        """What the installed build reports about itself - authoritative."""
        try:
            with open(shootergame_log(self.args.log), "r", encoding="utf-8",
                      errors="ignore") as f:
                m = re.search(r"CI server version:\s*(\S+)", f.read())
            return m.group(1) if m else None
        except OSError:
            return None

    def _api_version(self):
        """Optional second opinion - never fatal, the log value is primary."""
        try:
            status, data = http_json("https://valorant-api.com/v1/version",
                                     insecure_retry=True)
        except NetworkError as e:
            log(f"warning: {e}")
            return None
        if status == 200 and data:
            return data["data"]["riotClientVersion"]
        return None

    def _detect_client_version(self):
        # The game's own log beats valorant-api.com, which can lag a patch by
        # hours - and a version Riot doesn't recognise gets the request refused.
        self.version_log = self._log_version()
        self.version_api = self._api_version()
        self.client_version = self.version_log or self.version_api
        if not self.client_version:
            raise RiotAuthError("Could not determine the client version.")

    def build_variants(self):
        """Every (client version, user agent) pair worth trying, best first.

        A refusal can come from either - a version Riot doesn't recognise, or an
        edge block on the user agent - and from here there's no way to tell which
        without trying. So enumerate and rotate on refusal.
        """
        versions = [v for v in (self.version_log, self.version_api) if v]
        self.variants = [(v, ua) for v in versions for ua in UA_CANDIDATES]
        self.variant = 0

    def next_variant(self):
        """Advance to the next combination. False once they're exhausted."""
        if self.variant + 1 >= len(self.variants):
            return False
        self.variant += 1
        version, ua = self.variants[self.variant]
        self.client_version = version
        log(f"retrying as variant {self.variant + 1}/{len(self.variants)}: "
            f"{version}, ua={ua or 'urllib default'}")
        return True

    @property
    def game_version(self):
        """release-13.04-shipping-20-5340415 -> 13.04.00.5340415, which is the
        form the game itself puts in its user agent."""
        m = re.match(r"release-(\d+\.\d+)-\w+-\d+-(\d+)", self.client_version or "")
        return f"{m.group(1)}.00.{m.group(2)}" if m else (self.client_version or "")

    @property
    def user_agent(self):
        if not self.variants:
            return None
        template = self.variants[self.variant][1]
        if not template:
            return None
        return template.format(v=self.client_version, gv=self.game_version)

    @property
    def headers(self):
        h = {
            "Authorization": f"Bearer {self.access_token}",
            "X-Riot-Entitlements-JWT": self.entitlements,
            "X-Riot-ClientPlatform": CLIENT_PLATFORM,
            "X-Riot-ClientVersion": self.client_version,
        }
        if self.user_agent:
            h["User-Agent"] = self.user_agent
        return h

    @property
    def local(self):
        """Base url + headers for the Riot client's own localhost API."""
        return (f"https://127.0.0.1:{self.port}",
                {"Authorization": f"Basic {self.basic}"})

    @property
    def glz(self):
        return f"https://glz-{self.region}-1.{self.shard}.a.pvp.net"

    @property
    def pd(self):
        return f"https://pd-{self.shard}.a.pvp.net"


# -------------------------------------------------------------- asset catalog

CATALOG_SOURCES = {
    "weapons": "https://valorant-api.com/v1/weapons",
    "agents": "https://valorant-api.com/v1/agents?isPlayableCharacter=true",
    "maps": "https://valorant-api.com/v1/maps",
    "tiers": "https://valorant-api.com/v1/contenttiers",
    "buddies": "https://valorant-api.com/v1/buddies",
}


def build_catalog(cache_path):
    """Index every skin / skin level / chroma uuid so loadout ids resolve."""
    raw = {}
    fallback = None
    if cache_path and os.path.exists(cache_path):
        # Skins change on patch days, not hourly - a stale cache beats no app,
        # so age only decides whether to refresh, never whether to use it.
        stale = time.time() - os.path.getmtime(cache_path) > 24 * 3600
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            if set(cached) == set(CATALOG_SOURCES):
                if not stale:
                    raw = cached
                else:
                    raw, fallback = {}, cached
        except Exception:
            raw = {}
    if set(raw) != set(CATALOG_SOURCES):
        raw = {}
        try:
            for key, url in CATALOG_SOURCES.items():
                status, data = http_json(url, timeout=30, insecure_retry=True)
                if status != 200 or not data:
                    raise RuntimeError(
                        f"valorant-api.com fetch failed for {key} (HTTP {status})")
                raw[key] = data["data"]
        except (NetworkError, RuntimeError):
            # An expired cache is still far better than refusing to start.
            if fallback:
                log("warning: couldn't refresh the skin catalog - using the "
                    "cached copy")
                raw = fallback
            else:
                raise
        if cache_path and raw is not fallback:
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(raw, f)
            except OSError:
                pass

    cat = {"weapon_names": {}, "skins": {}, "levels": {}, "chromas": {},
           "agents": {}, "maps": {}, "tiers": {}, "buddies": {}}

    for tier in raw["tiers"]:
        color = (tier.get("highlightColor") or "")[:6]
        cat["tiers"][tier["uuid"].lower()] = {
            "name": tier.get("devName") or tier.get("displayName"),
            "color": f"#{color}" if len(color) == 6 else "#8b8b8b",
            "icon": tier.get("displayIcon"),
        }

    for w in raw["weapons"]:
        cat["weapon_names"][w["uuid"].lower()] = w["displayName"]
        for skin in w.get("skins") or []:
            su = skin["uuid"].lower()
            cat["skins"][su] = {
                "weapon": w["displayName"],
                "name": skin["displayName"],
                "tier": (skin.get("contentTierUuid") or "").lower(),
                "icon": skin.get("displayIcon"),
            }
            for lvl in skin.get("levels") or []:
                cat["levels"][lvl["uuid"].lower()] = {
                    "skin": su, "icon": lvl.get("displayIcon")}
            for ch in skin.get("chromas") or []:
                cat["chromas"][ch["uuid"].lower()] = {
                    "skin": su,
                    "name": ch.get("displayName"),
                    "icon": ch.get("displayIcon") or ch.get("fullRender"),
                }

    for a in raw["agents"]:
        cat["agents"][a["uuid"].lower()] = {
            "name": a["displayName"], "icon": a.get("displayIconSmall") or a.get("displayIcon")}
    for m in raw["maps"]:
        if m.get("mapUrl"):
            cat["maps"][m["mapUrl"].lower()] = m["displayName"]
    for b in raw["buddies"]:
        cat["buddies"][b["uuid"].lower()] = b["displayName"]
        for lvl in b.get("levels") or []:
            cat["buddies"][lvl["uuid"].lower()] = b["displayName"]
    return cat


# ----------------------------------------------------------------- collecting

class Collector(threading.Thread):
    daemon = True

    def __init__(self, args):
        super().__init__(name="collector")
        self.args = args
        self.auth = Auth(args)
        self.catalog = None
        self._lock = threading.Lock()
        self._state = {"status": "starting", "message": "Loading skin catalog...",
                       "players": [], "updated": time.time()}
        self._match_id = None
        self._probe = 0
        self._presence_debug = {}
        self._wake = threading.Event()

    # -- public
    def state(self):
        with self._lock:
            return dict(self._state)

    def poke(self):
        self._match_id = None
        self._wake.set()

    def diagnostics(self):
        """Everything needed to debug a bad state, with no secrets in it."""
        a = self.auth
        st = self.state()
        return {
            "status": st.get("status"),
            "message": st.get("message"),
            "phase": st.get("phase"),
            "lockfile_found": bool(a.port),
            "logged_in": bool(a.access_token),
            "puuid_prefix": (a.puuid or "")[:8],
            "region": a.region,
            "shard": a.shard,
            "client_version": a.client_version,
            "version_from_log": a.version_log,
            "version_from_api": a.version_api,
            "catalog_skins": len(self.catalog["skins"]) if self.catalog else 0,
            "players": len(st.get("players") or []),
            "platform": f"{sys.platform} python {sys.version.split()[0]}",
            "presence": dict(self._presence_debug),
            "variant": {
                "index": a.variant + 1,
                "of": len(a.variants),
                "user_agent": a.user_agent or "urllib default",
            },
            "last_remote_error": dict(LAST_REMOTE_ERROR),
            "recent_requests": list(RECENT),
        }

    def _set(self, **kw):
        with self._lock:
            self._state.update(kw, updated=time.time())

    def run(self):
        # Keep trying rather than dying: a DNS blip at launch used to leave the
        # app permanently stuck on an error with no way back but a restart.
        attempt = 0
        while not self.catalog:
            try:
                self.catalog = build_catalog(self.args.cache)
                log(f"catalog ready: {len(self.catalog['skins'])} skins")
            except Exception as e:
                attempt += 1
                self._set(status="error", players=[],
                          message=f"{e} Retrying... (attempt {attempt})")
                log(f"catalog attempt {attempt} failed: {e}")
                self._wake.wait(min(10 * attempt, 60))
                self._wake.clear()
        if self.args.demo:
            self._set(**demo_state(self.catalog))
            return
        self._set(status="idle", message="Waiting for the Riot client...")
        authed = False
        while True:
            try:
                if not authed:
                    self.auth.refresh()
                    authed = True
                    log(f"auth ok  region={self.auth.region} shard={self.auth.shard} "
                        f"version={self.auth.client_version}")
                self._tick()
            except RiotAuthError as e:
                authed = False
                self._match_id = None
                self._set(status="no_client", message=str(e), players=[])
            except RiotApiError as e:
                self._match_id = None
                log(f"api error: {e}")
                # A 400 here is nearly always a client version that has drifted
                # from the installed build; the game's own log is authoritative.
                if e.status in (400, 403) and self.auth.next_variant():
                    a = self.auth
                    self._set(status="idle",
                              message=f"Refused - trying combination "
                                      f"{a.variant + 1} of {len(a.variants)}.")
                else:
                    if e.status == 401:
                        authed = False   # worth a fresh token before giving up
                    self._set(status="api_error", message=str(e), players=[])
            except NetworkError as e:
                self._set(status="offline", players=[], message=str(e))
            except Exception as e:
                authed = False
                self._set(status="error", message=f"{type(e).__name__}: {e}")
            self._wake.wait(self.args.interval)
            self._wake.clear()

    # -- internals
    def _tick(self):
        """One pass. Localhost presence drives everything; the remote endpoints
        are only touched when the phase actually changes, so this can poll fast."""
        pres = self._presence() or {}
        # Read by search: these fields have lived at the top level and, more
        # recently, inside nested *PresenceData objects.
        loop = deep_get(pres, "sessionLoopState") or ""
        ctx = {
            "queue": deep_get(pres, "queueId") or "",
            "score": ([deep_get(pres, "partyOwnerMatchScoreAllyTeam"),
                       deep_get(pres, "partyOwnerMatchScoreEnemyTeam")]
                      if loop == "INGAME" else None),
            "map": self.catalog["maps"].get(
                str(deep_get(pres, "matchMap") or "").lower()),
        }
        if loop == "INGAME":
            self._ingame(ctx)
        elif loop == "PREGAME":
            self._pregame(ctx)
        elif loop == "MENUS":
            self._match_id = None
            self._set(status="idle", phase="menus", players=[], score=None,
                      message="In the menus. Queue up and this fills in.")
        else:
            # No usable presence. That can mean VALORANT isn't running, or that
            # presence itself is unreadable - so ask the game servers directly
            # rather than assuming. They're the source of truth for the roster;
            # presence is only ever an optimisation.
            self._probe += 1
            if self._probe % 3:
                return
            first = self._ingame(ctx, probe=True)
            if first == "match":
                return
            second = self._pregame(ctx, probe=True)
            if second == "match":
                return
            if "none" in (first, second):
                # Authenticated fine, simply not in a match: the healthy state.
                self._match_id = None
                self._set(status="idle", phase="menus", players=[], score=None,
                          message="Waiting for a match. (Presence unreadable, so "
                                  "this is polling the match endpoints directly.)")
            else:
                # Both endpoints refused us. Same treatment as the non-probe
                # path: rotate version/user-agent until something is accepted.
                a = self.auth
                if a.next_variant():
                    self._set(status="idle", players=[], score=None,
                              message=f"Riot refused the request - trying "
                                      f"combination {a.variant + 1} of "
                                      f"{len(a.variants)}.")
                else:
                    self._set(status="waiting_game", phase="unknown", players=[],
                              score=None,
                              message="Riot refused every version/user-agent "
                                      "combination. Open the diagnostics in "
                                      "how to use - the last_remote_error block "
                                      "says who rejected it.")

    def _presence(self):
        base, headers = self.auth.local
        status, data = http_json(f"{base}/chat/v4/presences", headers=headers,
                                 ctx=INSECURE, timeout=5)
        # Record why this failed, if it did - "presence came back empty" has
        # several possible causes and guessing between them wastes a release.
        dbg = self._presence_debug = {"http": status}
        if status != 200 or not data:
            return None
        entries = data.get("presences") or []
        dbg["count"] = len(entries)
        mine = [p for p in entries if p.get("puuid") == self.auth.puuid]
        dbg["own_entry"] = bool(mine)
        dbg["products"] = sorted({p.get("product") for p in entries
                                  if p.get("product")})
        if not mine:
            return None
        # One puuid can have several entries - the riot client's carries no
        # payload, the game's does. Take whichever actually has one.
        p = next((e for e in mine if e.get("private")), mine[0])
        dbg["own_entries"] = len(mine)
        dbg["own_product"] = p.get("product")
        dbg["has_private"] = bool(p.get("private"))
        if not p.get("private"):
            return None
        try:
            blob = json.loads(base64.b64decode(p["private"]))
        except Exception as e:
            dbg["decode_error"] = f"{type(e).__name__}"
            return None
        dbg["blob_keys"] = sorted(blob)[:24]
        # Riot moved these into nested *PresenceData objects at some point, so
        # record the shape and read them by search rather than by fixed path.
        dbg["nested"] = {k: sorted(v)[:14] for k, v in blob.items()
                         if isinstance(v, dict)}
        dbg["loop_state"] = deep_get(blob, "sessionLoopState")
        return blob

    def _ingame(self, ctx, probe=False):
        a = self.auth
        status, data = http_json(f"{a.glz}/core-game/v1/players/{a.puuid}",
                                 headers=a.headers)
        if status in (400, 401, 403):
            if probe:
                return "denied"
            raise RiotApiError("core-game/players", status, data)
        if status == 404 or not data or not data.get("MatchID"):
            return "none" if probe else False
        match_id = data["MatchID"]

        # Roster is locked for the match: fetch once, then only refresh the score.
        if match_id == self._match_id and self.state().get("players"):
            self._set(status="in_game", phase="ingame", score=ctx["score"])
            return "match"

        status, match = http_json(f"{a.glz}/core-game/v1/matches/{match_id}",
                                  headers=a.headers)
        if status != 200 or not match:
            self._set(status="idle", phase="ingame",
                      message=f"Match fetch failed (HTTP {status}).")
            return "match"
        status, loadouts = http_json(
            f"{a.glz}/core-game/v1/matches/{match_id}/loadouts", headers=a.headers)
        if status != 200 or not loadouts:
            self._set(status="idle", phase="ingame",
                      message=f"Loadout fetch failed (HTTP {status}).")
            return "match"

        players = self._build_players(match, loadouts)
        self._match_id = match_id
        map_name = (self.catalog["maps"].get((match.get("MapID") or "").lower())
                    or ctx["map"] or "Unknown map")
        mode = (match.get("ModeID") or "").rstrip("/").split("/")[-1] or "Standard"
        self._set(status="in_game", phase="ingame", message="", match_id=match_id,
                  map=map_name, mode=mode, queue=ctx["queue"], score=ctx["score"],
                  you=a.puuid, players=players)
        log(f"match {match_id[:8]} on {map_name}: {len(players)} loadouts")
        return "match"

    def _pregame(self, ctx, probe=False):
        """Agent select. Skins aren't published until the match starts, but the
        roster is - so the app fills in a phase early."""
        a = self.auth
        status, data = http_json(f"{a.glz}/pregame/v1/players/{a.puuid}",
                                 headers=a.headers)
        if status in (400, 401, 403):
            if probe:
                return "denied"
            raise RiotApiError("pregame/players", status, data)
        if status == 404 or not data or not data.get("MatchID"):
            return "none" if probe else False
        match_id = data["MatchID"]
        status, match = http_json(f"{a.glz}/pregame/v1/matches/{match_id}",
                                  headers=a.headers)
        if status != 200 or not match:
            return "none" if probe else False

        rows = ((match.get("AllyTeam") or {}).get("Players")) or []
        names = self._names([p["Subject"] for p in rows])
        players = []
        for p in rows:
            agent = self.catalog["agents"].get((p.get("CharacterID") or "").lower(), {})
            identity = p.get("PlayerIdentity") or {}
            locked = p.get("CharacterSelectionState") == "locked"
            players.append({
                "puuid": p["Subject"],
                "name": names.get(p["Subject"]) or "Unknown",
                "agent": agent.get("name") or ("picking" if not locked else "Unknown"),
                "agent_icon": agent.get("icon"),
                "team": (match.get("AllyTeam") or {}).get("TeamID"),
                "is_you": p["Subject"] == a.puuid,
                "is_teammate": True,
                "level": None if identity.get("HideAccountLevel") else identity.get("AccountLevel"),
                "locked": locked,
                "skins": [],
            })
        players.sort(key=lambda r: (not r["is_you"], r["name"].lower()))
        self._match_id = None  # force a loadout fetch once the match starts
        map_name = (self.catalog["maps"].get((match.get("MapID") or "").lower())
                    or ctx["map"] or "")
        self._set(status="pregame", phase="pregame", match_id=match_id,
                  map=map_name, mode="agent select", queue=ctx["queue"], score=None,
                  you=a.puuid, players=players,
                  message="Agent select - skins unlock the moment the match starts.")
        return "match"

    def _build_players(self, match, loadouts):
        entries = loadouts.get("Loadouts") or []
        rows = match.get("Players") or []
        my_team = next((p.get("TeamID") for p in rows
                        if p.get("Subject") == self.auth.puuid), None)

        # Loadout entries carry a CharacterID and are returned in the same
        # order as Players; Subject is often blank, so match on character
        # first and fall back to positional alignment.
        by_char = {}
        for i, e in enumerate(entries):
            inner = e.get("Loadout") or e
            char = (e.get("CharacterID") or inner.get("CharacterID") or "").lower()
            by_char.setdefault(char, []).append((i, inner))

        names = self._names([p["Subject"] for p in rows])
        out = []
        for i, p in enumerate(rows):
            char = (p.get("CharacterID") or "").lower()
            inner = None
            bucket = by_char.get(char)
            if bucket and len(bucket) == 1:
                inner = bucket[0][1]
            elif i < len(entries):
                inner = entries[i].get("Loadout") or entries[i]
            agent = self.catalog["agents"].get(char, {})
            identity = p.get("PlayerIdentity") or {}
            name = names.get(p["Subject"])
            if identity.get("Incognito") and p.get("TeamID") != my_team:
                name = agent.get("name", "Hidden")
            out.append({
                "puuid": p["Subject"],
                "name": name or agent.get("name") or "Unknown",
                "agent": agent.get("name", "Unknown"),
                "agent_icon": agent.get("icon"),
                "team": p.get("TeamID"),
                "is_you": p["Subject"] == self.auth.puuid,
                "is_teammate": p.get("TeamID") == my_team,
                "level": None if identity.get("HideAccountLevel") else identity.get("AccountLevel"),
                "skins": self._skins(inner or {}),
            })
        out.sort(key=lambda r: (not r["is_teammate"], not r["is_you"], r["name"].lower()))
        return out

    def _names(self, puuids):
        status, data = http_json(f"{self.auth.pd}/name-service/v2/players",
                                 method="PUT", headers=self.auth.headers, body=puuids)
        if status != 200 or not data:
            return {}
        return {e["Subject"]: f"{e['GameName']}#{e['TagLine']}" for e in data
                if e.get("GameName")}

    def _skins(self, loadout):
        cat = self.catalog
        skins = []
        for weapon_id, item in (loadout.get("Items") or {}).items():
            chroma = level = skin_uuid = None
            buddy = None
            for sock in (item.get("Sockets") or {}).values():
                sid = ((sock.get("Item") or {}).get("ID") or "").lower()
                if sid in cat["chromas"]:
                    chroma = sid
                elif sid in cat["levels"]:
                    level = sid
                elif sid in cat["skins"]:
                    skin_uuid = sid
                elif sid in cat["buddies"]:
                    buddy = cat["buddies"][sid]
            if chroma:
                skin_uuid = cat["chromas"][chroma]["skin"]
            elif level:
                skin_uuid = cat["levels"][level]["skin"]
            if not skin_uuid:
                continue
            skin = cat["skins"][skin_uuid]
            icon = None
            if chroma:
                icon = cat["chromas"][chroma]["icon"]
            if not icon and level:
                icon = cat["levels"][level]["icon"]
            icon = icon or skin["icon"]
            variant = cat["chromas"][chroma]["name"] if chroma else None
            if variant and variant.strip().lower() == skin["name"].strip().lower():
                variant = None
            tier = cat["tiers"].get(skin["tier"], {})
            skins.append({
                "weapon": cat["weapon_names"].get(weapon_id.lower(), "Weapon"),
                "skin": skin["name"],
                "variant": variant,
                "icon": icon,
                "buddy": buddy,
                "tier": tier.get("name"),
                "color": tier.get("color", "#8b8b8b"),
                "default": skin["name"].strip().lower().startswith("standard"),
            })
        order = {w: i for i, w in enumerate(WEAPON_ORDER)}
        skins.sort(key=lambda s: (order.get(s["weapon"], 99), s["weapon"]))
        return skins


def demo_state(cat):
    """Fake roster so the UI can be checked without Valorant running."""
    pool = {}
    for s in cat["skins"].values():
        if s["tier"] and not s["name"].lower().startswith("standard"):
            pool.setdefault(s["weapon"], []).append(s)
    agents = list(cat["agents"].values())
    players = []
    for i, nm in enumerate(["you#0000", "TrollTarget#NA1", "SkinCollector#EUW",
                            "BroketGaming#123", "PhantomOnly#000",
                            "enemy1#000", "enemy2#000", "enemy3#000",
                            "enemy4#000", "enemy5#000"]):
        agent = agents[i % len(agents)]
        skins = []
        for j, weapon in enumerate(["Vandal", "Phantom", "Operator", "Sheriff", "Melee"]):
            bucket = pool.get(weapon) or next(iter(pool.values()))
            s = bucket[(i * 37 + j * 101) % len(bucket)]
            tier = cat["tiers"].get(s["tier"], {})
            skins.append({"weapon": weapon, "skin": s["name"], "variant": None,
                          "icon": s["icon"], "buddy": None, "tier": tier.get("name"),
                          "color": tier.get("color", "#8b8b8b"), "default": False})
        players.append({"puuid": f"demo-{i}", "name": nm, "agent": agent["name"],
                        "agent_icon": agent["icon"], "team": "Blue" if i < 5 else "Red",
                        "is_you": i == 0, "is_teammate": i < 5,
                        "level": 40 + i * 13, "skins": skins})
    return {"status": "in_game", "message": "DEMO DATA - not a real match",
            "match_id": "demo", "map": "Ascent", "mode": "demo", "phase": "ingame",
            "score": [7, 5], "queue": "competitive",
            "you": "demo-0", "players": players}


# --------------------------------------------------------------------- server

PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>valskins</title><style>
*{box-sizing:border-box}
[hidden]{display:none !important}   /* id rules below would otherwise win */
body{margin:0;font:15px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif;
background:#0e1014;color:#e6e8ee}
header{position:sticky;top:0;z-index:5;display:flex;gap:14px;align-items:center;flex-wrap:wrap;
padding:12px 18px;background:#14171dee;backdrop-filter:blur(8px);border-bottom:1px solid #23272f}
h1{font-size:15px;margin:0;letter-spacing:.14em;text-transform:uppercase;color:#ff4655}
.pill{font-size:12px;padding:3px 9px;border-radius:999px;background:#1e2230;color:#9aa3b5}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:6px}
.live .dot{background:#3ddc84;box-shadow:0 0 8px #3ddc84}
.wait .dot{background:#ffb03a}.bad .dot{background:#ff4655}
main{padding:18px;max-width:1400px;margin:0 auto}
h2{font-size:12px;letter-spacing:.16em;text-transform:uppercase;color:#7b8496;margin:22px 0 10px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fill,minmax(390px,1fr))}
.card{background:#161a21;border:1px solid #232833;border-radius:12px;overflow:hidden}
.card.you{border-color:#3a4763}
.who{display:flex;align-items:center;gap:10px;padding:10px 12px;border-bottom:1px solid #21262f}
.who img{width:34px;height:34px;border-radius:8px;background:#0d1014}
.who b{font-size:14px}.who small{color:#78808f;display:block;font-size:11.5px}
.tag{margin-left:auto;font-size:11px;color:#6d7482}
.rows{padding:4px 0}
.row{display:flex;align-items:center;gap:10px;padding:6px 12px}
.row:hover{background:#1b202a}
.w{width:62px;flex:none;font-size:10.5px;color:#79808f;text-transform:uppercase;letter-spacing:.06em}
.thumb{width:74px;height:24px;flex:none;object-fit:contain;object-position:left center;opacity:.95}
.name{font-size:13.5px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.name span{color:#767d8b;font-size:11.5px}
.bar{width:3px;align-self:stretch;border-radius:2px;flex:none}
.muted{color:#767d8b}
.empty{padding:60px 20px;text-align:center;color:#767d8b}
#sharebox{font-size:13px;padding:12px 18px;background:#171c26;
border-bottom:1px solid #232833;color:#c3cad6}
.sharehead{margin-bottom:9px}
#sharelist{display:flex;flex-direction:column;gap:6px;margin-bottom:9px}
.sharerow{display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.sharerow code{background:#0f1319;border:1px solid #2b3140;border-radius:6px;
padding:3px 9px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#7fd6a5}
.sharerow .idx{width:74px;flex:none;font-size:11px;text-transform:uppercase;
letter-spacing:.06em;color:#79808f}
button{font:inherit;font-size:12px;padding:5px 11px;border-radius:8px;border:1px solid #2b3140;
background:#1b2029;color:#c9cfdb;cursor:pointer}button:hover{border-color:#3d4557}
.tabs{display:flex;margin-right:4px;border:1px solid #2b3140;border-radius:9px;
overflow:hidden;flex:none}
.tab{border:none;border-radius:0;background:#12161d;color:#8d96a7;padding:6px 14px}
.tab:hover{background:#1b2029;color:#c9cfdb}
.tab.on{background:#ff4655;color:#fff;font-weight:600}
.tab.on:hover{background:#ff4655;color:#fff}
#help{max-width:820px;font-size:14.5px;color:#c3cad6}
#help h2:first-child{margin-top:6px}
#help p{margin:0 0 12px}
#help b{color:#e6e8ee}
#help code{background:#1b2029;border:1px solid #2b3140;border-radius:5px;padding:1px 6px;
font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;white-space:nowrap}
#diagout{background:#0f1319;border:1px solid #2b3140;border-radius:8px;padding:12px;
font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;
line-height:1.5;color:#a8b4c4;max-height:320px;overflow:auto;user-select:all}
.steps{padding-left:20px;margin:0}
.steps li{margin-bottom:10px}
table.ref{border-collapse:collapse;width:100%;margin-bottom:6px}
table.ref td{border-top:1px solid #21262f;padding:9px 12px 9px 0;vertical-align:top}
table.ref td:first-child{width:37%;white-space:normal}
table.ref .pill{white-space:nowrap;font-size:11.5px}
</style></head><body>
<header>
  <h1>valskins</h1>
  <span class="tabs">
    <button onclick="setView('roster')" id="tab-roster" class="tab on">roster</button>
    <button onclick="setView('help')" id="tab-help" class="tab">how to use</button>
  </span>
  <span id="status" class="pill wait"><span class="dot"></span><span id="statustext">connecting</span></span>
  <span class="pill" id="meta"></span>
  <button onclick="toggleEnemies()" id="enemybtn">show enemies</button>
  <button onclick="refresh(true)">refresh</button>
  <button onclick="share()" id="sharebtn" hidden>watch on another device</button>
  <span class="pill muted" id="age"></span>
</header>
<div id="sharebox" hidden>
  <div class="sharehead">Open one of these on your Mac or phone &mdash; this PC has more
    than one address, so try the first and work down:</div>
  <div id="sharelist"></div>
  <div class="muted">Same network only. Links stop working when you close valskins.</div>
</div>
<main id="out"><div class="empty">loading&hellip;</div></main>

<main id="help" hidden>
  <h2>Getting started</h2>
  <ol class="steps">
    <li>Start VALORANT and log in as usual. valskins reads its identity from the
      Riot client on this PC, so <b>there is nothing to log into here</b> &mdash; and
      any tool that asks for your Riot password is trying to steal it.</li>
    <li>Open valskins any time before or during a match. It reconnects on its own.</li>
    <li>Queue up. Agent select fills in your teammates; every weapon skin appears
      the instant round&nbsp;1 starts.</li>
  </ol>

  <h2>What the status pill means</h2>
  <table class="ref">
    <tr><td><span class="pill wait"><span class="dot"></span>client not running</span></td>
      <td>VALORANT isn't open yet, or you're still sitting on the login screen.</td></tr>
    <tr><td><span class="pill wait"><span class="dot"></span>waiting for match</span></td>
      <td>Connected and idle in the menus. This is the healthy resting state.</td></tr>
    <tr><td><span class="pill live"><span class="dot"></span>agent select</span></td>
      <td>Your team's names and agents are in. Skins aren't published by the game
        until the match actually forms.</td></tr>
    <tr><td><span class="pill live"><span class="dot"></span>live</span></td>
      <td>Full roster with loadouts. The round score keeps updating.</td></tr>
  </table>

  <h2>Reading a card</h2>
  <p>One row per weapon, skipping default skins. The coloured bar is rarity:
    <b style="color:#5a9fe2">Select</b>, <b style="color:#009587">Deluxe</b>,
    <b style="color:#d1548d">Premium</b>, <b style="color:#f5955b">Exclusive</b>,
    <b style="color:#facc15">Ultra</b>. Grey italics after a skin name is the chroma
    variant or gun buddy. <b>show enemies</b> reveals the other team &mdash; their names
    respect the game's incognito setting.</p>

  <h2>Watching on another device</h2>
  <p>Click <b>watch on another device</b> and open the link on a Mac, phone or second
    monitor &mdash; useful when VALORANT is fullscreen. Both screens stay live at once.
    The link carries a token that changes every time valskins starts, so closing the
    app kills every old link.</p>
  <p>If this PC has more than one network adapter &mdash; ethernet plus Wi&#8209;Fi, or a
    VPN installed &mdash; you'll get several links. Only one of them is reachable from
    your other device, so work down the list. Wired and wireless on the same router
    reach each other fine; a guest network won't.</p>
  <p class="muted">Windows will ask about the firewall the first time. Allow it on
    <b>private</b> networks &mdash; that prompt is what lets your other device connect.</p>

  <h2>If something looks wrong</h2>
  <table class="ref">
    <tr><td><code>client not running</code> and it won't budge</td>
      <td>Get past the Riot login screen. valskins can't see anything until the
        client has a session.</td></tr>
    <tr><td>Stuck on <code>waiting for match</code> during a real game</td>
      <td>Region autodetect probably failed. Launch with
        <code>valskins.exe --region na --shard na</code> (your region).</td></tr>
    <tr><td><code>link is missing its token</code></td>
      <td>You opened the share URL without the <code>?token=&hellip;</code> part.
        Copy it again from the button above.</td></tr>
    <tr><td><code>valskins unreachable</code> on the other device</td>
      <td>Try the next address in the share list. Otherwise: Windows Firewall, or the
        wired network is marked <b>Public</b> instead of Private (Settings &rarr;
        Network &rarr; Ethernet), or the two devices aren't on the same router.</td></tr>
    <tr><td>Names show as agents instead of riot&nbsp;ids</td>
      <td>Those players are hidden by the game's incognito setting. Nothing to fix.</td></tr>
    <tr><td>Everything empty right after a patch</td>
      <td>These are undocumented endpoints and Riot moves them sometimes. Check for a
        newer release.</td></tr>
  </table>

  <h2>Still stuck?</h2>
  <p>Grab the diagnostics and paste them wherever you're getting help &mdash; status,
    region, client version and the last handful of requests with their HTTP codes.
    No tokens, no riot id, no puuid beyond its first few characters.</p>
  <p><button onclick="copyDiag(this)">copy diagnostics</button>
    <span class="muted" style="margin-left:8px">or open
    <code>/api/diag</code></span></p>
  <pre id="diagout" hidden></pre>

  <h2>What it does and doesn't do</h2>
  <p>It calls the same endpoints the game client calls, plus a public asset site for
    skin names and icons. It is read&#8209;only: no game memory, no injection, nothing
    written anywhere, and deliberately <b>not</b> an overlay &mdash; it's an ordinary
    window you alt&#8209;tab to, because drawing on top of the game is the part that
    carries real risk. Unofficial and not endorsed by Riot Games.</p>
</main>
<script>
let showEnemies = false, last = 0;
// A LAN viewer opens the page with ?token=...; every poll has to carry it too.
const TOKEN = new URLSearchParams(location.search).get('token');
function toggleEnemies(){ showEnemies = !showEnemies; document.getElementById('enemybtn').textContent =
  showEnemies ? 'hide enemies' : 'show enemies'; render(window._s); }
function esc(s){ return (s??'').toString().replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

function setView(v){
  document.getElementById('out').hidden = v !== 'roster';
  document.getElementById('help').hidden = v !== 'help';
  document.getElementById('tab-roster').className = 'tab' + (v === 'roster' ? ' on' : '');
  document.getElementById('tab-help').className = 'tab' + (v === 'help' ? ' on' : '');
  try{ localStorage.setItem('valskins.view', v); }catch(e){}
}

function share(){
  const box = document.getElementById('sharebox');
  box.hidden = !box.hidden;
  document.getElementById('sharebtn').textContent =
    box.hidden ? 'watch on another device' : 'hide link';
}
function copyShare(url, btn){
  navigator.clipboard.writeText(url);
  btn.textContent = 'copied';
  setTimeout(() => btn.textContent = 'copy', 1500);
}

async function copyDiag(btn){
  try{
    const q = TOKEN ? '?token=' + encodeURIComponent(TOKEN) : '';
    const text = await (await fetch('/api/diag' + q, {cache:'no-store'})).text();
    const out = document.getElementById('diagout');
    out.textContent = text; out.hidden = false;
    await navigator.clipboard.writeText(text);
    btn.textContent = 'copied to clipboard';
  }catch(e){
    btn.textContent = 'copy failed - select the text below';
  }
  setTimeout(() => btn.textContent = 'copy diagnostics', 2500);
}

function renderShare(urls){
  document.getElementById('sharebtn').hidden = false;
  document.querySelector('.sharehead').textContent = urls.length > 1
    ? 'Open one of these on your Mac or phone — this PC has more than one address, ' +
      'so try the first and work down:'
    : 'Open this on your Mac or phone:';
  const list = document.getElementById('sharelist');
  if(list.dataset.urls === urls.join()) return;   // don't clobber "copied" labels
  list.dataset.urls = urls.join();
  list.innerHTML = urls.map((u, i) => `
    <div class="sharerow">
      <span class="idx">${urls.length > 1 ? (i === 0 ? 'try first' : 'or') : ''}</span>
      <code>${esc(u)}</code>
      <button onclick="copyShare('${esc(u)}', this)">copy</button>
    </div>`).join('');
}

function card(p){
  const rows = p.skins.filter(s => !s.default).map(s => `
    <div class="row">
      <div class="bar" style="background:${esc(s.color)}"></div>
      <div class="w">${esc(s.weapon)}</div>
      ${s.icon ? `<img class="thumb" src="${esc(s.icon)}" loading="lazy">` : '<div class="thumb"></div>'}
      <div class="name">${esc(s.skin)}${s.variant ? ` <span>${esc(s.variant)}</span>` : ''}${
        s.buddy ? ` <span>&middot; ${esc(s.buddy)}</span>` : ''}</div>
    </div>`).join('');
  return `<div class="card${p.is_you ? ' you' : ''}">
    <div class="who">
      ${p.agent_icon ? `<img src="${esc(p.agent_icon)}">` : ''}
      <div><b>${esc(p.name)}</b><small>${esc(p.agent)}${p.level ? ' &middot; lvl ' + p.level : ''}</small></div>
      <span class="tag">${p.is_you ? 'you' : ''}</span>
    </div>
    <div class="rows">${rows || `<div class="row muted" style="padding:10px 12px">${
      p.skins.length === 0 && p.locked !== undefined
        ? (p.locked ? 'locked in – skins load at match start' : 'still picking…')
        : 'all default skins'}</div>`}</div>
  </div>`;
}

function render(s){
  if(!s) return;
  window._s = s;
  const st = document.getElementById('status'), txt = document.getElementById('statustext');
  st.className = 'pill ' + ({in_game:'live', pregame:'live', idle:'wait',
                             starting:'wait', waiting_game:'wait'}[s.status] || 'bad');
  txt.textContent = {in_game:'live', pregame:'agent select', idle:'waiting for match',
                     starting:'starting', no_client:'riot client not running',
                     waiting_game:'waiting for VALORANT', api_error:'riot rejected us',
                     offline:'network problem', error:'error'}[s.status] || s.status;
  const bits = [];
  if(s.map) bits.push(s.map);
  if(s.mode) bits.push(s.mode);
  if(s.score && s.score[0] !== null && s.score[0] !== undefined)
    bits.push(`${s.score[0]} – ${s.score[1]}`);
  if(s.message) bits.push(s.message);
  document.getElementById('meta').textContent = bits.join('  ·  ');
  if(s.lan_urls && s.lan_urls.length) renderShare(s.lan_urls);
  const out = document.getElementById('out');
  const mine = (s.players || []).filter(p => p.is_teammate);
  const theirs = (s.players || []).filter(p => !p.is_teammate);
  if(!mine.length && !theirs.length){
    out.innerHTML = `<div class="empty">${esc(s.message || 'nothing yet')}
      <div style="margin-top:16px"><button onclick="setView('help')">how to use valskins</button></div>
    </div>`;
    return;
  }
  let html = `<h2>your team</h2><div class="grid">${mine.map(card).join('')}</div>`;
  if(showEnemies && theirs.length)
    html += `<h2>enemies</h2><div class="grid">${theirs.map(card).join('')}</div>`;
  out.innerHTML = html;
}

async function refresh(force){
  try{
    const q = new URLSearchParams();
    if(TOKEN) q.set('token', TOKEN);
    if(force) q.set('poke', '1');
    const qs = q.toString();
    const r = await fetch('/api/state' + (qs ? '?' + qs : ''), {cache:'no-store'});
    if(!r.ok) throw new Error('HTTP ' + r.status);
    const s = await r.json(); last = Date.now(); render(s);
  }catch(e){
    document.getElementById('status').className = 'pill bad';
    document.getElementById('statustext').textContent =
      /403/.test(e.message) ? 'link is missing its token' : 'valskins unreachable';
  }
}
// First launch lands on the instructions; after that it remembers your last tab.
let storedView = null;
try{ storedView = localStorage.getItem('valskins.view'); }catch(e){}
setView(storedView || 'help');

setInterval(refresh, 2000);
setInterval(() => { document.getElementById('age').textContent =
  last ? Math.round((Date.now()-last)/1000) + 's ago' : ''; }, 500);
refresh();
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    collector = None
    token = None
    lan_urls = ()           # shown in the UI so the app needs no console
    protocol_version = "HTTP/1.1"

    @property
    def is_loopback(self):
        return self.client_address[0] in ("127.0.0.1", "::1")

    def authorized(self, query):
        """The app's own window is always allowed; anything off-box needs the
        token when one is set."""
        if self.is_loopback or not self.token:
            return True
        return query.get("token", [None])[0] == self.token

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype):
        body = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if not self.authorized(query):
            self._send(403, "forbidden: this link needs its ?token=...\n", "text/plain")
            return
        if parsed.path in ("/", "/index.html"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif parsed.path == "/api/state":
            if query.get("poke"):
                self.collector.poke()
            state = self.collector.state()
            # Only the local window is told the share links (they carry the token).
            if self.is_loopback and self.lan_urls:
                state["lan_urls"] = list(self.lan_urls)
            self._send(200, json.dumps(state), "application/json")
        elif parsed.path == "/api/diag":
            self._send(200, json.dumps(self.collector.diagnostics(), indent=2),
                       "application/json")
        else:
            self._send(404, "not found\n", "text/plain")


def main():
    p = argparse.ArgumentParser(description="Valorant teammate skin viewer")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--host", default="0.0.0.0", help="0.0.0.0 to reach it from your Mac")
    p.add_argument("--interval", type=float, default=1.0,
                   help="poll seconds (localhost presence, so this is cheap)")
    p.add_argument("--token", help="require ?token=X on requests (LAN privacy)")
    p.add_argument("--region", help="override, e.g. na")
    p.add_argument("--shard", help="override, e.g. na")
    p.add_argument("--client-version", help="override X-Riot-ClientVersion")
    p.add_argument("--lockfile", help="path to the Riot Client lockfile")
    p.add_argument("--log", help="path to ShooterGame.log")
    p.add_argument("--cache", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                   ".catalog.json"))
    p.add_argument("--demo", action="store_true", help="fake roster; works anywhere")
    p.add_argument("--open", action="store_true", help="open the UI in a browser")
    args = p.parse_args()

    collector = Collector(args)
    collector.start()
    Handler.collector = collector
    Handler.token = args.token
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    suffix = f"?token={args.token}" if args.token else ""
    log(f"local:  http://127.0.0.1:{args.port}/")
    if args.host == "0.0.0.0":
        Handler.lan_urls = [f"http://{ip}:{args.port}/{suffix}" for ip in lan_ips()]
        for url in Handler.lan_urls:
            log(f"on your Mac / phone:  {url}")
    if args.open:
        webbrowser.open(f"http://127.0.0.1:{args.port}/{suffix}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("bye")


if __name__ == "__main__":
    main()
