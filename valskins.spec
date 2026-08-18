# PyInstaller spec -> a single valskins.exe with no console window.
# Built on a Windows runner; see .github/workflows/build.yml.
# onefile is implied by handing binaries+datas straight to EXE with no COLLECT.
import os

from PyInstaller.utils.hooks import collect_all

datas, binaries, hiddenimports = collect_all("webview")
# The Windows backend is chosen at runtime, so PyInstaller can't see it statically.
hiddenimports += [
    "webview.platforms.edgechromium",
    "webview.platforms.winforms",
    "clr_loader",
]

icon = "web/valskins.ico" if os.path.exists("web/valskins.ico") else None

a = Analysis(
    ["app.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "test", "unittest"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name="valskins",
    debug=False,
    strip=False,
    upx=False,
    console=False,
    icon=icon,
)
