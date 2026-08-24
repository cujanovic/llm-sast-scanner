#!/bin/sh
set -eu

PROGRAM=llm-sast-scanner-bootstrap
REPOSITORY=https://github.com/cujanovic/llm-sast-scanner
REF=main
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/llm-sast-bootstrap.XXXXXX") || { printf '%s: cannot create temporary directory\n' "$PROGRAM" >&2; exit 1; }
FORWARD=$TMP_ROOT/arguments
: > "$FORWARD"
fail() { printf '%s: error: %s\n' "$PROGRAM" "$*" >&2; exit 1; }
cleanup() { rm -rf "$TMP_ROOT"; }
trap cleanup EXIT HUP INT TERM

while [ "$#" -gt 0 ]; do
    case $1 in
        --ref) [ "$#" -ge 2 ] || fail '--ref requires a tag or commit'; REF=$2; shift 2 ;;
        *) case $1 in *"
"*) fail 'arguments may not contain newlines' ;; esac; printf '%s\n' "$1" >> "$FORWARD"; shift ;;
    esac
done
case $REF in ''|*[!A-Za-z0-9._/-]*|/*|*/../*|../*|*/..) fail 'invalid ref' ;; esac
case $REF in main) URL=$REPOSITORY/archive/refs/heads/main.tar.gz ;; *) URL=$REPOSITORY/archive/$REF.tar.gz ;; esac
ARCHIVE=$TMP_ROOT/source.tar.gz
if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --proto-redir '=https' -o "$ARCHIVE" "$URL" || fail 'download failed'
elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$ARCHIVE" "$URL" || fail 'download failed'
else
    fail 'curl or wget is required'
fi
LIST=$TMP_ROOT/archive.list
VERBOSE=$TMP_ROOT/archive.verbose
tar -tzf "$ARCHIVE" > "$LIST" || fail 'cannot list source archive'
[ -s "$LIST" ] || fail 'source archive is empty'
root=
while IFS= read -r member; do
    [ ${#member} -le 500 ] || fail 'archive path is too long'
    case $member in /*|./*|*/./*|*/.|../*|*/../*|*/..|*'//'*) fail "unsafe archive path: $member" ;; esac
    candidate=${member%%/*}
    case $candidate in llm-sast-scanner-*) : ;; *) fail "unexpected archive root: $candidate" ;; esac
    [ -n "$root" ] || root=$candidate
    [ "$root" = "$candidate" ] || fail 'archive has multiple roots'
done < "$LIST"
tar -tvzf "$ARCHIVE" > "$VERBOSE" || fail 'cannot inspect source archive'
while IFS= read -r entry; do case $entry in [-dl]*) : ;; *) fail 'archive contains an unsupported entry type' ;; esac; done < "$VERBOSE"
EXTRACTED=$TMP_ROOT/extracted
mkdir "$EXTRACTED"
tar -xzf "$ARCHIVE" -C "$EXTRACTED" \
    "$root/install.sh" "$root/install.ps1" \
    "$root/llm-sast-scanner" "$root/llm-sast-scanner-convergence-loop" "$root/llm-sast-scanner-full-scan-loop" || fail 'cannot extract required source files'
SOURCE=$EXTRACTED/$root
[ -f "$SOURCE/install.sh" ] || fail 'archive is missing install.sh'
for skill in llm-sast-scanner llm-sast-scanner-convergence-loop llm-sast-scanner-full-scan-loop; do
    [ -d "$SOURCE/$skill" ] && [ ! -L "$SOURCE/$skill" ] && [ -f "$SOURCE/$skill/SKILL.md" ] || fail "archive is missing required skill: $skill"
    [ -z "$(find "$SOURCE/$skill" -type l -print | sed -n '1p')" ] || fail "required skill contains a link: $skill"
done
set --
while IFS= read -r argument; do set -- "$@" "$argument"; done < "$FORWARD"
sh "$SOURCE/install.sh" "$@"
