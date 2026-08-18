#!/usr/bin/env python3
"""valskins desktop app - the double-clickable wrapper around the collector.

Runs the collector plus a loopback-only web server, then puts a real native
window in front of it (WebView2 on Windows, WebKit on macOS). No browser, no
terminal, no login: the Riot client on this machine supplies the identity.

Built into valskins.exe by .github/workflows/build.yml.
"""

import argparse
import os
import secrets
import socket
import sys
import threading

import webview

from valskins import Collector, Handler, lan_ips, log
from http.server import ThreadingHTTPServer


def free_port(preferred):
    """Prefer the documented port so bookmarks keep working, else anything free."""
    for candidate in (preferred, 0):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", candidate))
            return s.getsockname()[1]
        except OSError:
            continue
        finally:
            s.close()
    raise RuntimeError("no free port")


class Args:
    """The collector expects argparse-shaped config; keep the app's own flags thin."""
    region = shard = client_version = lockfile = log = token = None
    interval = 1.0
    demo = False
    cache = None


def main():
    p = argparse.ArgumentParser(description="valskins desktop app")
    p.add_argument("--loopback-only", action="store_true",
                   help="don't listen on the LAN at all")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--demo", action="store_true", help="fake match, no Valorant needed")
    p.add_argument("--region", help="override region, e.g. na")
    p.add_argument("--shard", help="override shard, e.g. na")
    p.add_argument("--debug", action="store_true", help="webview devtools")
    opts = p.parse_args()

    args = Args()
    args.demo = opts.demo
    args.region, args.shard = opts.region, opts.shard
    # PyInstaller unpacks to a temp dir, so cache next to the exe instead.
    base = (os.path.dirname(sys.executable) if getattr(sys, "frozen", False)
            else os.path.dirname(os.path.abspath(__file__)))
    args.cache = os.path.join(base, ".catalog.json")

    collector = Collector(args)
    collector.start()

    Handler.collector = collector
    # Listening on the LAN costs nothing until someone has the token, and the
    # window can't show a share link for a socket it never opened. Off-box
    # requests without the token get a 403; the local window never needs it.
    Handler.token = None if opts.loopback_only else secrets.token_urlsafe(6)
    host = "127.0.0.1" if opts.loopback_only else "0.0.0.0"
    port = free_port(opts.port)
    server = ThreadingHTTPServer((host, port), Handler)
    if Handler.token:
        Handler.lan_urls = [f"http://{ip}:{port}/?token={Handler.token}"
                            for ip in lan_ips()]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log(f"ui on http://127.0.0.1:{port}/")
    for url in Handler.lan_urls:
        log(f"share {url}")

    webview.create_window("valskins", f"http://127.0.0.1:{port}/",
                          width=1180, height=880, min_size=(720, 520),
                          background_color="#0e1014")
    webview.start(debug=opts.debug)
    server.shutdown()


if __name__ == "__main__":
    main()
