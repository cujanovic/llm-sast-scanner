#!/bin/sh
set -eu

usage() {
    printf 'usage: sh install.sh [install|doctor]\n' >&2
    exit 1
}

[ "$#" -eq 1 ] || usage
case $1 in
    install|doctor) command=$1 ;;
    *) usage ;;
esac

script=$0
case $script in
    */*) : ;;
    *) script=./$script ;;
esac
source_root=$(CDPATH= cd "$(dirname "$script")" && pwd -P)

for skill in \
    llm-sast-scanner \
    llm-sast-scanner-convergence-loop \
    llm-sast-scanner-full-scan-loop
do
    [ -f "$source_root/$skill/SKILL.md" ] || {
        printf 'missing: %s/SKILL.md\n' "$source_root/$skill" >&2
        exit 1
    }
done

[ -n "${HOME:-}" ] || {
    printf 'HOME is not set\n' >&2
    exit 1
}

if [ "$command" = install ]; then
    for root in "$HOME/.claude/skills" "$HOME/.agents/skills"; do
        mkdir -p "$root"
        for skill in \
            llm-sast-scanner \
            llm-sast-scanner-convergence-loop \
            llm-sast-scanner-full-scan-loop
        do
            destination="$root/$skill"
            source_dir="$source_root/$skill"
            if [ -e "$destination" ] || [ -L "$destination" ]; then
                rm -rf "$destination"
            fi
            ln -s "$source_dir" "$destination"
        done
    done
    exit 0
fi

invalid=0
for root in "$HOME/.claude/skills" "$HOME/.agents/skills"; do
    for skill in \
        llm-sast-scanner \
        llm-sast-scanner-convergence-loop \
        llm-sast-scanner-full-scan-loop
    do
        destination="$root/$skill"
        expected="$source_root/$skill"
        if [ ! -L "$destination" ]; then
            printf 'invalid: %s\n' "$destination" >&2
            invalid=1
            continue
        fi
        if ! link_target=$(readlink "$destination"); then
            printf 'invalid: %s\n' "$destination" >&2
            invalid=1
            continue
        fi
        if [ "$link_target" != "$expected" ]; then
            printf 'invalid: %s\n' "$destination" >&2
            invalid=1
            continue
        fi
        if [ ! -r "$expected/SKILL.md" ]; then
            printf 'invalid: %s\n' "$destination" >&2
            invalid=1
            continue
        fi
        printf 'ok: %s\n' "$destination"
    done
done

exit "$invalid"
