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
        self.good_variant = None

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
        else:
            # Fresh token after an expiry: the combination didn't change, so
            # don't carry over a rotation that a stale token provoked.
            self.reset_variant()
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
        self.good_variant = None

    def _apply_variant(self):
        self.client_version = self.variants[self.variant][0]

    def confirm_variant(self):
        """Riot accepted a request with the current combination. Remember it, so
        a later hiccup - an expired token, say - can't walk us off it."""
        if self.good_variant != self.variant:
            self.good_variant = self.variant
            log(f"variant {self.variant + 1}/{len(self.variants)} accepted")

    def reset_variant(self):
        """Go back to the combination known to work, or to the first one."""
        target = self.good_variant if self.good_variant is not None else 0
        if self.variant != target:
            self.variant = target
            self._apply_variant()
            log(f"back to variant {target + 1}/{len(self.variants)}")

    def next_variant(self):
        """Advance to the next combination. False once they're exhausted, and
        rewinds rather than leaving us parked on one that doesn't work."""
        if self.variant + 1 >= len(self.variants):
            self.reset_variant()
            return False
        self.variant += 1
        self._apply_variant()
        version, ua = self.variants[self.variant]
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
        # pd.{shard}, not pd-{shard} - the latter doesn't resolve at all.
        return f"https://pd.{self.shard}.a.pvp.net"


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
                self._set(**self._on_refusal(e))
                if e.status == 401:
                    authed = False       # token probably expired; get a new one
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
                # Both endpoints refused us - same policy as the non-probe path.
                self._set(**self._on_refusal())

    def _on_refusal(self, err=None):
        """What to do when Riot turns a request away.

        Rotating combinations is only the right move while we've never had one
        accepted. Once a combination is known good, a refusal is a passing
        problem - an expired token, a Riot blip - and rotating away from a
        working setup makes it permanent until the app is restarted.
        """
        a = self.auth
        status = getattr(err, "status", 403)
        if status == 401:
            return {"status": "api_error", "players": [],
                    "message": "Session expired - getting a new token."}
        if a.good_variant is None and a.next_variant():
            return {"status": "idle", "players": [], "score": None,
                    "message": f"Riot refused the request - trying combination "
                               f"{a.variant + 1} of {len(a.variants)}."}
        a.reset_variant()
        detail = f" ({err})" if err else ""
        return {"status": "api_error", "players": [],
                "message": f"Riot refused that request{detail} Retrying."}

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
        # Anything other than a refusal means these headers are accepted - a 404
        # here just means "not in a match", which is still a passing handshake.
        a.confirm_variant()
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
        # Anything other than a refusal means these headers are accepted - a 404
        # here just means "not in a match", which is still a passing handshake.
        a.confirm_variant()
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
        """Riot ids. Cosmetic next to the skins, so never let this sink a roster -
        the agent name stands in when it fails."""
        try:
            status, data = http_json(f"{self.auth.pd}/name-service/v2/players",
                                     method="PUT", headers=self.auth.headers,
                                     body=puuids)
        except NetworkError as e:
            log(f"warning: names unavailable ({e})")
            return {}
        if status != 200 or not data:
            log(f"warning: name-service returned HTTP {status}")
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
<title>valskins</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root{
  /* light is the designed default; dark is a real theme, not an inversion */
  --bg:#fbf6ee; --wash-a:#e9f4fb; --wash-b:#fdf0e3;
  --surface:#ffffff; --surface-2:#f8f3ec; --chip:#eaf1f7;
  --ink:#25333f; --ink-2:#5d7183; --ink-3:#93a4b2;
  --line:#f0e7da; --line-2:#e7ebef;
  --baby:#8fd0ee; --baby-deep:#3f9fd0; --baby-ink:#1f7ba7; --baby-wash:#e8f5fc;
  --mint:#3fb489; --amber:#dd9a2e; --rose:#dc6a69;
  /* your own card: warm sand, so it belongs to the cream rather than
     competing with the blue chrome or the status colours */
  --mine:#d9bb8c; --mine-wash:#f6ecda; --mine-ink:#8a6a3f;
  --shad:30 60 85; --shad-a:.05; --shad-b:.16;
  --r:18px;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --bg:#121922; --wash-a:#172836; --wash-b:#1d2029;
    --surface:#1a2330; --surface-2:#212c3a; --chip:#243040;
    --ink:#e9eff5; --ink-2:#a2b5c4; --ink-3:#71879a;
    --line:#25313e; --line-2:#25313e;
    --baby:#79c6e9; --baby-deep:#4aa8d8; --baby-ink:#9bd9f3; --baby-wash:#1c2c39;
    --mint:#57c79c; --amber:#e5b45f; --rose:#e58786;
    --mine:#b6905c; --mine-wash:#2b2620; --mine-ink:#e0c193;
    --shad:0 0 0; --shad-a:.25; --shad-b:.45;
  }
}
:root[data-theme="dark"]{
  --bg:#121922; --wash-a:#172836; --wash-b:#1d2029;
  --surface:#1a2330; --surface-2:#212c3a; --chip:#243040;
  --ink:#e9eff5; --ink-2:#a2b5c4; --ink-3:#71879a;
  --line:#25313e; --line-2:#25313e;
  --baby:#79c6e9; --baby-deep:#4aa8d8; --baby-ink:#9bd9f3; --baby-wash:#1c2c39;
  --mint:#57c79c; --amber:#e5b45f; --rose:#e58786;
  --mine:#b6905c; --mine-wash:#2b2620; --mine-ink:#e0c193;
  --shad:0 0 0; --shad-a:.25; --shad-b:.45;
}

*{box-sizing:border-box}
[hidden]{display:none !important}

body{margin:0;color:var(--ink);background:var(--bg);
font:15px/1.55 Nunito,"Segoe UI Variable Text","Segoe UI",-apple-system,
BlinkMacSystemFont,sans-serif;
background-image:radial-gradient(1200px 420px at 8% -10%, var(--wash-a) 0%, transparent 68%),
                 radial-gradient(980px 360px at 95% -6%, var(--wash-b) 0%, transparent 62%);
background-attachment:fixed;
transition:background-color .3s ease, color .3s ease}

/* -------------------------------------------------------------- app bar */
/* Light UIs separate with space, not outlines - so: one hairline, no boxes. */
header{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:18px;
flex-wrap:wrap;padding:14px 22px;background:color-mix(in srgb, var(--bg) 88%, transparent);
backdrop-filter:blur(12px);border-bottom:1px solid var(--line)}
h1{font-size:17px;margin:0;font-weight:800;letter-spacing:-.02em;color:var(--ink);
display:flex;align-items:center;gap:8px}
h1::before{content:"";width:9px;height:9px;border-radius:50%;
background:linear-gradient(140deg,var(--baby),var(--baby-deep))}

.tabs{display:flex;gap:2px;padding:3px;background:var(--surface-2);border-radius:12px;
flex:none}
.tab{border:none;background:transparent;color:var(--ink-2);padding:6px 15px;
border-radius:9px;font-weight:600;font-size:12.5px}
.tab:hover{background:var(--surface);color:var(--ink);box-shadow:none;transform:none}
.tab.on{background:var(--surface);color:var(--baby-ink);
box-shadow:0 1px 3px rgb(var(--shad) / var(--shad-a))}
.tab.on:hover{background:var(--surface)}

.state{display:flex;align-items:baseline;gap:9px;min-width:0}
.state b{font-weight:700;font-size:13px;color:var(--ink)}
.state .meta{font-size:12.5px;color:var(--ink-3);white-space:nowrap;overflow:hidden;
text-overflow:ellipsis}
.dot{width:8px;height:8px;border-radius:50%;flex:none;align-self:center;
background:var(--ink-3)}
.live .dot{background:var(--mint);animation:beat 2s ease-in-out infinite}
.live b{color:var(--mint)}
.wait .dot{background:var(--amber);animation:breathe 2.6s ease-in-out infinite}
.bad .dot{background:var(--rose)}
.bad b{color:var(--rose)}

.actions{margin-left:auto;display:flex;align-items:center;gap:6px;flex:none}
button{font:inherit;font-weight:600;font-size:12.5px;padding:7px 13px;border-radius:10px;
border:none;background:transparent;color:var(--ink-2);cursor:pointer;
transition:background .16s, color .16s, transform .14s cubic-bezier(.2,.8,.3,1)}
button:hover{background:var(--baby-wash);color:var(--baby-ink)}
button:active{transform:scale(.97)}
.icon{padding:7px 10px;font-size:14px;line-height:1}
.age{font-size:11.5px;color:var(--ink-3);min-width:52px;text-align:right}

/* ---------------------------------------------------------------- roster */
main{padding:24px 22px 40px;max-width:1440px;margin:0 auto}
h2{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--ink-3);
margin:0 0 14px;font-weight:700}
h2:not(:first-child){margin-top:30px}
.grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fill,minmax(370px,1fr))}

/* No border - elevation alone, which is what reads as "light" rather than
   "dark theme with the colours flipped". */
.card{background:var(--surface);border-radius:var(--r);overflow:hidden;
box-shadow:0 1px 2px rgb(var(--shad) / var(--shad-a)),
0 14px 32px -20px rgb(var(--shad) / var(--shad-b));
transition:transform .24s cubic-bezier(.2,.8,.3,1), box-shadow .24s;
animation:rise .5s cubic-bezier(.2,.75,.3,1) both;
animation-delay:calc(var(--i,0) * 45ms)}
.card:hover{transform:translateY(-3px);
box-shadow:0 2px 4px rgb(var(--shad) / var(--shad-a)),
0 26px 44px -24px rgb(var(--shad) / var(--shad-b))}
.card.you{box-shadow:0 0 0 2px var(--mine),
0 16px 34px -20px rgb(var(--shad) / var(--shad-b))}

.who{display:flex;align-items:center;gap:12px;padding:15px 17px 13px}
.who img{width:38px;height:38px;border-radius:12px;background:var(--chip)}
.who b{font-size:14.5px;font-weight:700;letter-spacing:-.01em}
.who small{color:var(--ink-3);display:block;font-size:11.5px;font-weight:600}
.tag{margin-left:auto;font-size:10px;letter-spacing:.1em;text-transform:uppercase;
font-weight:700;color:var(--mine-ink);background:var(--mine-wash);padding:4px 9px;
border-radius:999px}

.rows{padding:0 8px 10px}
.row{display:flex;align-items:center;gap:12px;padding:7px 9px;border-radius:11px;
transition:background .16s}
.row:hover{background:var(--baby-wash)}
.row:hover .thumb{transform:scale(1.05)}
/* A dot, not a full-height bar: bars are a dark-UI device. */
.pip{width:7px;height:7px;border-radius:50%;flex:none;
filter:saturate(1.1) brightness(.94)}
.w{width:58px;flex:none;font-size:9.5px;font-weight:700;color:var(--ink-3);
text-transform:uppercase;letter-spacing:.09em}
.thumb{width:74px;height:26px;flex:none;object-fit:contain;object-position:center;
padding:1px 4px;border-radius:8px;background:var(--chip);
transition:transform .22s cubic-bezier(.2,.8,.3,1)}
.name{font-size:13.5px;min-width:0;overflow:hidden;text-overflow:ellipsis;
white-space:nowrap;font-weight:600}
.name span{color:var(--ink-3);font-size:11.5px;font-weight:600;font-style:normal}
.muted{color:var(--ink-3)}
.empty{padding:72px 20px;text-align:center;color:var(--ink-3);font-weight:600;
animation:rise .45s cubic-bezier(.2,.75,.3,1) both}

/* ----------------------------------------------------------------- share */
#sharebox{font-size:13px;padding:16px 22px;background:var(--baby-wash);
border-bottom:1px solid var(--line);animation:drop .3s ease both}
.sharehead{margin-bottom:11px;font-weight:600}
#sharelist{display:flex;flex-direction:column;gap:8px;margin-bottom:10px}
.sharerow{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.sharerow code{background:var(--surface);border-radius:9px;padding:5px 11px;
font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
color:var(--baby-ink);box-shadow:0 1px 2px rgb(var(--shad) / var(--shad-a))}
.sharerow .idx{width:70px;flex:none;font-size:10px;text-transform:uppercase;
letter-spacing:.09em;font-weight:700;color:var(--ink-3)}
.sharerow button{background:var(--surface);
box-shadow:0 1px 2px rgb(var(--shad) / var(--shad-a))}

/* ------------------------------------------------------------------ help */
#help{animation:rise .4s cubic-bezier(.2,.75,.3,1) both}
.doc{display:grid;grid-template-columns:196px minmax(0,1fr);gap:34px;
align-items:start;max-width:1020px}

/* sidebar */
.doc-nav{position:sticky;top:88px;display:flex;flex-direction:column;gap:2px}
.doc-link{text-align:left;padding:8px 12px;border-radius:10px;font-size:13px;
font-weight:600;color:var(--ink-2);position:relative}
.doc-link:hover{background:var(--surface);color:var(--ink)}
.doc-link.on{background:var(--surface);color:var(--baby-ink);
box-shadow:0 1px 2px rgb(var(--shad) / var(--shad-a))}
.doc-link.on::before{content:"";position:absolute;left:0;top:9px;bottom:9px;width:3px;
border-radius:2px;background:var(--baby-deep)}

/* article */
.doc-body{min-width:0;max-width:660px}
.doc-sec{animation:rise .34s cubic-bezier(.2,.75,.3,1) both}
.doc-sec h3{margin:0 0 6px;font-size:23px;font-weight:800;letter-spacing:-.02em;
color:var(--ink)}
.doc-sec h4{margin:28px 0 7px;font-size:13.5px;font-weight:800;color:var(--ink);
letter-spacing:.01em}
.doc-sec p{margin:0 0 13px;color:var(--ink-2);font-size:14.5px}
.doc-sec .lead{font-size:16px;color:var(--ink-2);margin-bottom:22px;line-height:1.6}
.doc-sec b{color:var(--ink);font-weight:700}
.doc-sec code{background:var(--surface);border-radius:7px;padding:2px 8px;
font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;
white-space:nowrap;box-shadow:0 1px 2px rgb(var(--shad) / var(--shad-a))}

.callout{background:var(--baby-wash);border-radius:14px;padding:15px 17px;
margin:0 0 22px;font-size:14px;color:var(--ink-2);
border-left:3px solid var(--baby-deep)}
.callout b{color:var(--ink)}

.pill{display:inline-flex;align-items:center;gap:7px;font-size:11.5px;font-weight:700;
padding:4px 11px;border-radius:999px;background:var(--surface);color:var(--ink-2);
box-shadow:0 1px 2px rgb(var(--shad) / var(--shad-a));white-space:nowrap}
button.solid{background:var(--surface);color:var(--ink);
box-shadow:0 1px 2px rgb(var(--shad) / var(--shad-a))}
button.solid:hover{background:var(--baby-wash);color:var(--baby-ink)}

#diagout{background:var(--surface);border-radius:14px;padding:16px;margin:14px 0 0;
font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;line-height:1.6;
color:var(--ink-2);max-height:320px;overflow:auto;user-select:all;
box-shadow:0 1px 2px rgb(var(--shad) / var(--shad-a)),
0 10px 26px -20px rgb(var(--shad) / var(--shad-b))}
.steps{padding-left:20px;margin:0 0 13px;color:var(--ink-2);font-size:14.5px}
.steps li{margin-bottom:11px}
table.ref{border-collapse:collapse;width:100%;font-size:14px}
table.ref td{border-top:1px solid var(--line-2);padding:12px 14px 12px 0;
vertical-align:top;color:var(--ink-2)}
table.ref td:first-child{width:40%}
table.ref tr:first-child td{border-top:none}

/* stack the nav into a scrollable row when the window is narrow */
@media (max-width:860px){
  .doc{grid-template-columns:1fr;gap:18px}
  .doc-nav{position:static;flex-direction:row;overflow-x:auto;padding-bottom:4px;
  gap:4px}
  .doc-link{white-space:nowrap;flex:none}
  .doc-link.on::before{display:none}
}

/* -------------------------------------------------------------- keyframes */
@keyframes rise{from{opacity:0;transform:translateY(12px) scale(.99)}
to{opacity:1;transform:none}}
@keyframes drop{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:none}}
@keyframes beat{0%,100%{box-shadow:0 0 0 0 rgb(63 180 137 / .5)}
70%{box-shadow:0 0 0 7px rgb(63 180 137 / 0)}}
@keyframes breathe{0%,100%{opacity:1}50%{opacity:.4}}
@keyframes bump{0%{transform:scale(1)}35%{transform:scale(1.13)}100%{transform:scale(1)}}
.bumped{display:inline-block;animation:bump .45s cubic-bezier(.2,.8,.3,1)}

@media (prefers-reduced-motion: reduce){
  *,*::before,*::after{animation:none !important;transition:none !important}
  .card:hover{transform:none}
}
</style></head><body>
<header>
  <h1>valskins</h1>
  <span class="tabs">
    <button onclick="setView('roster')" id="tab-roster" class="tab on">roster</button>
    <button onclick="setView('help')" id="tab-help" class="tab">how to use</button>
  </span>
  <span id="status" class="state wait">
    <span class="dot"></span><b id="statustext">connecting</b>
    <span class="meta" id="meta"></span>
  </span>
  <span class="actions">
    <button onclick="toggleEnemies()" id="enemybtn">show enemies</button>
    <button onclick="refresh(true)">refresh</button>
    <button onclick="share()" id="sharebtn" hidden>watch on another device</button>
    <span class="age" id="age"></span>
    <button class="icon" id="themebtn" onclick="toggleTheme()" title="switch theme"></button>
  </span>
</header>
<div id="sharebox" hidden>
  <div class="sharehead">Open one of these on your Mac or phone &mdash; this PC has more
    than one address, so try the first and work down:</div>
  <div id="sharelist"></div>
  <div class="muted">Same network only. Links stop working when you close valskins.</div>
</div>
<main id="out"><div class="empty">loading&hellip;</div></main>

<main id="help" hidden>
<div class="doc">
  <nav class="doc-nav" id="docnav">
    <button class="doc-link on" onclick="setSection('start')" data-sec="start">Getting started</button>
    <button class="doc-link" onclick="setSection('roster')" data-sec="roster">Reading the roster</button>
    <button class="doc-link" onclick="setSection('status')" data-sec="status">Status meanings</button>
    <button class="doc-link" onclick="setSection('share')" data-sec="share">Second screen</button>
    <button class="doc-link" onclick="setSection('trouble')" data-sec="trouble">Troubleshooting</button>
    <button class="doc-link" onclick="setSection('safety')" data-sec="safety">Safety &amp; privacy</button>
    <button class="doc-link" onclick="setSection('internals')" data-sec="internals">Under the hood</button>
  </nav>

  <div class="doc-body">
    <section class="doc-sec" id="sec-start">
      <h3>Getting started</h3>
      <p class="lead">valskins shows every weapon skin your teammates have equipped,
        from the moment a match forms.</p>

      <div class="callout">
        <b>There is nothing to log into.</b> valskins reads who you are from the Riot
        client already running on this PC. Any tool that asks for your Riot password
        is trying to steal your account &mdash; this one never asks, and never could.
      </div>

      <h4>First run</h4>
      <ol class="steps">
        <li>Start VALORANT and log in as usual.</li>
        <li>Open valskins. It says <b>waiting for match</b> once it's connected, which
          is the healthy resting state.</li>
        <li>Queue up. Agent select fills in names and agents; every skin appears the
          instant round&nbsp;1 begins.</li>
      </ol>

      <h4>Day to day</h4>
      <p>Leave it open for the whole session &mdash; it reconnects on its own, survives
        queue dodges and match changes, and costs almost nothing while you're in the
        menus. Order doesn't matter either: start it before or after VALORANT.</p>
    </section>

    <section class="doc-sec" id="sec-roster" hidden>
      <h3>Reading the roster</h3>
      <p class="lead">One card per player, one row per weapon, default skins hidden.</p>

      <h4>The dot</h4>
      <p>The coloured dot on each row is the skin's rarity &mdash;
        <b style="color:#3f88c5">Select</b>, <b style="color:#00806f">Deluxe</b>,
        <b style="color:#c23f7e">Premium</b>, <b style="color:#cf6a26">Exclusive</b>,
        <b style="color:#9a7500">Ultra</b>. Hover it and it names the tier.</p>

      <h4>Names and variants</h4>
      <p>The smaller grey text after a skin is its chroma variant or the gun buddy
        attached to it. Your own card is outlined and tagged <b>you</b>.</p>

      <h4>The other team</h4>
      <p><b>show enemies</b> reveals their loadouts too. Names respect the game's
        incognito setting, so hidden players show as their agent instead.</p>

      <h4>Weapons shown</h4>
      <p>Everything a player owns a skin for, ordered Vandal, Phantom, Operator,
        Sheriff, knife, then the rest. Collectors get tall cards.</p>
    </section>

    <section class="doc-sec" id="sec-status" hidden>
      <h3>What the status means</h3>
      <p class="lead">The dot and label at the top of the window say exactly where in
        the chain things are.</p>
      <table class="ref">
        <tr><td><span class="pill"><span class="dot" style="background:var(--amber)"></span>riot client not running</span></td>
          <td>VALORANT isn't open, or you're still on the login screen.</td></tr>
        <tr><td><span class="pill"><span class="dot" style="background:var(--amber)"></span>waiting for VALORANT</span></td>
          <td>The Riot launcher is up but the game itself isn't. A launcher-only
            session can't see matches.</td></tr>
        <tr><td><span class="pill"><span class="dot" style="background:var(--amber)"></span>waiting for match</span></td>
          <td>Connected and idle in the menus. Everything is working.</td></tr>
        <tr><td><span class="pill"><span class="dot" style="background:var(--mint)"></span>agent select</span></td>
          <td>Names and agents are in. The game doesn't publish skins until the match
            actually forms.</td></tr>
        <tr><td><span class="pill"><span class="dot" style="background:var(--mint)"></span>live</span></td>
          <td>Full roster with loadouts. The round score keeps updating.</td></tr>
        <tr><td><span class="pill"><span class="dot" style="background:var(--rose)"></span>riot rejected us</span></td>
          <td>A request was refused. It retries by itself; see Troubleshooting.</td></tr>
        <tr><td><span class="pill"><span class="dot" style="background:var(--rose)"></span>network problem</span></td>
          <td>A host couldn't be reached at all. The message names which one.</td></tr>
      </table>
    </section>

    <section class="doc-sec" id="sec-share" hidden>
      <h3>Watching on a second screen</h3>
      <p class="lead">Useful when VALORANT is fullscreen: read the roster on a laptop,
        phone or second monitor while you play.</p>

      <h4>How</h4>
      <p>Click <b>watch on another device</b> and open the link it gives you. Both
        screens stay live at once. The link carries a token that changes every time
        valskins starts, so closing the app invalidates every old link.</p>

      <h4>If you get several links</h4>
      <p>A PC with more than one network adapter &mdash; ethernet plus Wi&#8209;Fi, or a
        VPN installed &mdash; has several addresses and only one is reachable from your
        other device. They're listed best guess first; work down the list.</p>

      <h4>When it won't connect</h4>
      <p>Wired and wireless reach each other fine on the same router. A guest network
        won't. Windows will ask about the firewall the first time &mdash; allow it on
        <b>private</b> networks, and check that the network isn't marked <b>Public</b>
        under Settings &rarr; Network, which blocks incoming connections regardless.</p>
    </section>

    <section class="doc-sec" id="sec-trouble" hidden>
      <h3>Troubleshooting</h3>
      <p class="lead">Most states resolve themselves within a few seconds. These are
        the ones that don't.</p>
      <table class="ref">
        <tr><td><code>riot client not running</code> that won't budge</td>
          <td>Get past the Riot login screen &mdash; there's no session to read until
            you do.</td></tr>
        <tr><td>Stuck on <code>waiting for match</code> during a real game</td>
          <td>Region autodetect may have failed. Start it as
            <code>valskins.exe --region na --shard na</code> for your region.</td></tr>
        <tr><td><code>riot rejected us</code> that persists</td>
          <td>It cycles through client version and user-agent combinations on its own.
            If none are accepted, the diagnostics below say whether the refusal came
            from Riot or from their edge.</td></tr>
        <tr><td><code>network problem</code></td>
          <td>The message names the host. If it's valorant-api.com, skin names come
            from a cached copy and the app keeps working.</td></tr>
        <tr><td><code>link is missing its token</code></td>
          <td>The share URL was opened without its <code>?token=</code> part. Copy it
            again.</td></tr>
        <tr><td>Names show as agents</td>
          <td>Those players are hidden by the game's incognito setting. Nothing to
            fix.</td></tr>
        <tr><td>Everything empty right after a patch</td>
          <td>These endpoints are undocumented and Riot moves them. Check for a newer
            release.</td></tr>
      </table>

      <h4>Diagnostics</h4>
      <p>Status, region, both candidate client versions, the presence shape it found,
        and the last 14 requests with their status codes. No tokens, no riot id, and
        your puuid truncated to a few characters.</p>
      <p><button class="solid" onclick="copyDiag(this)">copy diagnostics</button>
        <span class="muted" style="margin-left:9px">or open <code>/api/diag</code></span></p>
      <pre id="diagout" hidden></pre>
    </section>

    <section class="doc-sec" id="sec-safety" hidden>
      <h3>Safety &amp; privacy</h3>
      <p class="lead">What this does, and deliberately doesn't do.</p>

      <h4>Read-only</h4>
      <p>It calls the same endpoints the game client calls, plus a public asset site
        for skin names and icons. No game memory is read, nothing is injected, and
        nothing is written anywhere.</p>

      <h4>Not an overlay</h4>
      <p>It's an ordinary window you alt&#8209;tab to. Drawing on top of the game is
        the part that carries real risk, so it doesn't.</p>

      <h4>Your data stays here</h4>
      <p>Everything is fetched by this PC and shown on this PC. Nothing is uploaded,
        no account is created, no telemetry is sent. The second-screen link only
        works on your own network, only with its token, and only while the app is
        open.</p>

      <h4>The honest caveat</h4>
      <p>This is unofficial software using undocumented endpoints, and it is not
        endorsed by Riot Games. A patch can break it at any time.</p>
    </section>

    <section class="doc-sec" id="sec-internals" hidden>
      <h3>Under the hood</h3>
      <p class="lead">The chain, in order, for anyone curious or debugging.</p>
      <ol class="steps">
        <li>The Riot client's <b>lockfile</b> gives a local port and password.</li>
        <li>The local <b>entitlements</b> endpoint returns an access token, an
          entitlements JWT and your puuid.</li>
        <li>Region and shard come from the <code>glz-</code> URL in the game's own
          <b>ShooterGame.log</b>.</li>
        <li>The client version comes from that log too &mdash; it beats the public API,
          which can lag a patch by hours.</li>
        <li>Local <b>presence</b> reports the phase (menus, agent select, in game),
          the map and the live score, so the remote endpoints are only touched when
          the phase changes.</li>
        <li><b>pregame</b> or <b>core-game</b> returns the roster and teams.</li>
        <li><b>loadouts</b> returns equipped skin uuids for all ten players.</li>
        <li>The <b>name service</b> turns puuids into riot ids, and
          valorant-api.com turns skin uuids into names, rarities and icons.</li>
      </ol>
      <p>Skin uuids resolve by looking every socket id up in a prebuilt
        skin/level/chroma index, rather than trusting fixed socket uuids that Riot
        occasionally reshuffles.</p>
    </section>
  </div>
</div>
</main>
<script>
let showEnemies = false, last = 0, lastSig = '', lastScore = '';
// A LAN viewer opens the page with ?token=...; every poll has to carry it too.
const TOKEN = new URLSearchParams(location.search).get('token');
function toggleEnemies(){ showEnemies = !showEnemies; document.getElementById('enemybtn').textContent =
  showEnemies ? 'hide enemies' : 'show enemies'; lastSig = ''; render(window._s); }
function esc(s){ return (s??'').toString().replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

// Three states: an explicit light or dark choice, or no choice at all - in which
// case the OS setting decides and the button reflects whatever that resolves to.
function currentTheme(){
  const set = document.documentElement.getAttribute('data-theme');
  if(set) return set;
  return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
function applyTheme(t){
  document.documentElement.setAttribute('data-theme', t);
  const b = document.getElementById('themebtn');
  b.textContent = t === 'dark' ? '☀' : '☾';
  b.title = t === 'dark' ? 'switch to light' : 'switch to dark';
}
function toggleTheme(){
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  try{ localStorage.setItem('valskins.theme', next); }catch(e){}
  applyTheme(next);
}

function setSection(id){
  document.querySelectorAll('.doc-sec').forEach(function(sec){
    sec.hidden = sec.id !== 'sec-' + id;
  });
  document.querySelectorAll('.doc-link').forEach(function(a){
    a.className = 'doc-link' + (a.dataset.sec === id ? ' on' : '');
  });
  document.querySelector('.doc-body').scrollIntoView({block:'nearest'});
  try{ localStorage.setItem('valskins.section', id); }catch(e){}
}

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
      <span class="pip" style="background:${esc(s.color)}" title="${esc(s.tier || '')}"></span>
      <div class="w">${esc(s.weapon)}</div>
      ${s.icon ? `<img class="thumb" src="${esc(s.icon)}" loading="lazy">` : '<div class="thumb"></div>'}
      <div class="name">${esc(s.skin)}${s.variant ? ` <span>${esc(s.variant)}</span>` : ''}${
        s.buddy ? ` <span>&middot; ${esc(s.buddy)}</span>` : ''}</div>
    </div>`).join('');
  return `<div class="card${p.is_you ? ' you' : ''}" style="--i:${p._i || 0}">
    <div class="who">
      ${p.agent_icon ? `<img src="${esc(p.agent_icon)}">` : ''}
      <div><b>${esc(p.name)}</b><small>${esc(p.agent)}${p.level ? ' &middot; lvl ' + p.level : ''}</small></div>
      ${p.is_you ? '<span class="tag">you</span>' : ''}
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
  st.className = 'state ' + ({in_game:'live', pregame:'live', idle:'wait',
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
  const meta = document.getElementById('meta');
  meta.textContent = bits.join('  ·  ');
  // Give the round score a little kick whenever it moves.
  const score = JSON.stringify(s.score || null);
  if(score !== lastScore && lastScore && s.score){
    meta.classList.remove('bumped');
    void meta.offsetWidth;              // restart the animation
    meta.classList.add('bumped');
  }
  lastScore = score;
  if(s.lan_urls && s.lan_urls.length) renderShare(s.lan_urls);
  const out = document.getElementById('out');
  const mine = (s.players || []).filter(p => p.is_teammate);
  const theirs = (s.players || []).filter(p => !p.is_teammate);

  // Only touch the DOM when something actually changed. Rebuilding every poll
  // would restart every entrance animation twice a second.
  const sig = JSON.stringify([s.status, s.message, showEnemies, s.players]);
  if(sig === lastSig) return;
  lastSig = sig;

  if(!mine.length && !theirs.length){
    out.innerHTML = `<div class="empty">${esc(s.message || 'nothing yet')}
      <div style="margin-top:18px"><button onclick="setView('help')">how to use valskins</button></div>
    </div>`;
    return;
  }
  // Stagger the entrance in reading order, teammates first.
  [...mine, ...theirs].forEach((p, i) => p._i = i);
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
let storedTheme = null;
try{ storedTheme = localStorage.getItem('valskins.theme'); }catch(e){}
applyTheme(storedTheme || currentTheme());

let storedSection = null;
try{ storedSection = localStorage.getItem('valskins.section'); }catch(e){}
setSection(storedSection || 'start');

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
