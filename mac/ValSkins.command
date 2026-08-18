#!/bin/bash
# Double-click this on the Mac to open the viewer in its own window.
#
# First run, pass the share link that valskins.exe shows on the PC
# ("watch on another device" -> copy):
#
#   ./ValSkins.command 'http://192.168.1.42:8787/?token=abc123'
#
# It remembers it, so after that you can just double-click the file.
CONF="$HOME/.valskins-url"

if [ -n "$1" ]; then
  echo "$1" > "$CONF"
fi
if [ ! -s "$CONF" ]; then
  echo "Paste the share link from valskins on your PC"
  echo "(the 'watch on another device' button), or just the PC's IP:"
  read -r ANSWER
  [ -z "$ANSWER" ] && exit 1
  case "$ANSWER" in
    http*) echo "$ANSWER" > "$CONF" ;;
    *)     echo "http://${ANSWER}:${VALSKINS_PORT:-8787}/" > "$CONF" ;;
  esac
fi
URL="$(tr -d '[:space:]' < "$CONF")"

echo "opening $URL"
if [ -d "/Applications/Google Chrome.app" ]; then
  open -na "Google Chrome" --args --app="$URL" --window-size=1200,900
else
  open "$URL"
fi
