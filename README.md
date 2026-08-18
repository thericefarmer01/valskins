# valskins

Shows every equipped weapon skin on your team the second a Valorant match starts —
skin, chroma variant, rarity, gun buddy — before anyone gets to mention theirs.

A single Windows `.exe`. No installer, no admin, **no login**.

## Why there is no login screen

Because it doesn't need one, and the version that asks for your Riot password is the
version that steals your account. The app runs on the same PC as Valorant, so the
Riot client hands it a session token through its own lockfile — it already knows who
you are before the window opens. Every legitimate tool in this category (Blitz,
Tracker, rank-yoinker) works exactly this way.

## Using it

1. Grab `valskins.exe` from the [releases page](../../releases/latest).
2. Run it. SmartScreen will flag the unknown publisher — *More info → Run anyway* —
   because the build isn't code signed.
3. Start Valorant, then open valskins. It shows **waiting for match** once connected.
4. Queue up. Agent select fills the roster in; skins land the instant round 1 starts.

Flags, if you want them:

| flag | why |
| --- | --- |
| `--demo` | fake match, works with Valorant closed |
| `--region na --shard na` | if region autodetect fails |
| `--loopback-only` | refuse LAN connections entirely |
| `--debug` | webview devtools |

## Watching on your Mac while you play on the PC

No flags, no config. In the app on the PC, click **watch on another device** — it
lists a link for every private address this machine has, best guess first:

```
try first  http://192.168.1.42:8787/?token=k3Rt9x     <- ethernet
or         http://192.168.1.77:8787/?token=k3Rt9x     <- wifi
or         http://10.8.0.6:8787/?token=k3Rt9x         <- vpn adapter
```

A gaming PC usually has several (ethernet, wifi, a VPN or Hyper-V adapter) and only
one is reachable from the other device, so it lists them all instead of guessing.
Open one on the Mac (or phone, or second monitor) and you get the same live view
while Valorant stays fullscreen.

Ethernet on the PC and wifi on the Mac is fine as long as both hang off the same
router. A guest SSID won't work, and Windows marking the wired network **Public**
instead of Private will block it regardless of the firewall prompt. [mac/ValSkins.command](mac/ValSkins.command) will remember the link and
open it in its own window:

```bash
./mac/ValSkins.command 'http://192.168.1.42:8787/?token=k3Rt9x'
```

How the sharing is scoped:

- The app listens on the LAN, but **off-box requests need the token**; the app's own
  window is exempt because it comes from loopback.
- The token is random per launch, so closing valskins invalidates every share link.
- The link is only ever sent to the loopback window — a LAN viewer can't read it out
  of the API and re-share it.
- Windows Firewall will prompt on first launch. Allow it on **private** networks
  only; that prompt is what lets the Mac connect.

## Live behaviour

The loop polls the Riot client's **localhost** presence endpoint every second, which
is free, and only touches the remote match endpoints when the phase actually changes:

```
MENUS   → idle
PREGAME → agent select roster (names, agents, lock-in state)
INGAME  → full roster + loadouts, then score-only updates for the rest of the match
```

So match start → skins on screen is about a second, and a whole match costs three
remote requests. Loadouts are locked when the match forms, so re-fetching them would
be pointless.

## Layout

| file | what |
| --- | --- |
| [valskins.py](valskins.py) | the engine: auth, presence/phase loop, skin resolution, web UI. Zero dependencies, runs standalone with `python valskins.py` |
| [app.py](app.py) | desktop shell — loopback server + a native window (WebView2) |
| [valskins.spec](valskins.spec) | PyInstaller → one `valskins.exe`, no console |
| [.github/workflows/build.yml](.github/workflows/build.yml) | builds the exe on a Windows runner, smoke-tests it, attaches it to a release, publishes the site |
| [web/index.html](web/index.html) | the download page (GitHub Pages) |
| [mac/ValSkins.command](mac/ValSkins.command) | Mac launcher for the `--lan` view |

## Publishing it

PyInstaller can't cross-compile, so the exe is built by CI on Windows — you never
need Python on your gaming PC.

```bash
gh repo create valskins --public --source . --push
```

Then in the repo's *Settings → Pages*, set source to **GitHub Actions**, edit the one
marked line in `web/index.html` with your username, and tag a release:

```bash
git tag v0.1.0 && git push --tags
```

That produces `https://<user>.github.io/valskins` with a download button pointing at
`releases/latest/download/valskins.exe`.

Two distribution realities worth knowing: an unsigned exe always shows the SmartScreen
warning (a code-signing cert is a few hundred dollars a year), and PyInstaller
one-file builds occasionally trip antivirus heuristics. Both are cosmetic-but-annoying,
and both are why the source is worth keeping public.

## How it gets the data

1. `%LOCALAPPDATA%\Riot Games\Riot Client\Config\lockfile` → local API port + password.
2. `127.0.0.1:{port}/entitlements/v1/token` → access token, entitlements JWT, your puuid.
3. Region/shard from the `glz-` URL in `ShooterGame.log` (falls back to `/riotclient/region-locale`).
4. `127.0.0.1:{port}/chat/v4/presences` → phase, map, live score (base64 `private` blob).
5. `pregame/v1/...` or `core-game/v1/matches/{id}` → roster and teams.
6. `core-game/v1/matches/{id}/loadouts` → equipped skin/chroma uuids for all ten players.
7. `name-service/v2/players` → riot ids. [valorant-api.com](https://valorant-api.com) → names, rarities, icons.

Skin uuids resolve by looking every socket id up in a prebuilt skin/level/chroma
index, rather than trusting hardcoded socket uuids that Riot occasionally reshuffles.
Standard-issue skins are hidden; the asset catalog is cached for a day.

## Notes

- **Read-only.** The same endpoints the game client calls, plus a public asset CDN.
  No game memory, no injection, no writes.
- **Not an overlay** — an ordinary alt-tab window. Drawing on the game is the part
  that carries real risk, so it doesn't.
- Unofficial, undocumented endpoints, not endorsed by Riot: a patch can break it.
- Enemies are behind a toggle and respect the in-game incognito flag.
