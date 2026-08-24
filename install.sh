#!/bin/sh
set -eu

PROGRAM=llm-sast-scanner-installer
MARKER=.llm-sast-scanner-managed
MARKER_TEXT=llm-sast-scanner-managed-v1
SKILLS='llm-sast-scanner llm-sast-scanner-convergence-loop llm-sast-scanner-full-scan-loop'
COMMAND=install
PROJECT=
YES=0
DRY_RUN=0
QUIET=0
RUNTIMES=
RUNTIME_SET=0
TMP_ROOT=
ACTIVE=
TAB=$(printf '\t')

usage() {
    cat <<'EOF'
Usage: install.sh [install|doctor|uninstall] [options]

Options:
  --project PATH       Use project-local runtime directories
  --runtime NAME       Select claude, agents, devin, or all (repeatable)
  --yes                Non-interactive selection and legacy-link migration
  --dry-run            Show changes without writing them
  --quiet              Suppress normal output
  -h, --help           Show this help

Run install again to update managed copies.
EOF
}
fail() { printf '%s: error: %s\n' "$PROGRAM" "$*" >&2; exit 1; }
say() { [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"; }
add_runtime() {
    case $1 in
        claude|agents|devin) case " $RUNTIMES " in *" $1 "*) : ;; *) RUNTIMES="$RUNTIMES $1" ;; esac ;;
        all) add_runtime claude; add_runtime agents; add_runtime devin ;;
        *) fail "unknown runtime: $1" ;;
    esac
    RUNTIME_SET=1
}
command_set=0
while [ "$#" -gt 0 ]; do
    case $1 in
        install|doctor|uninstall) [ "$command_set" -eq 0 ] || fail 'only one command may be specified'; COMMAND=$1; command_set=1; shift ;;
        --project) [ "$#" -ge 2 ] || fail '--project requires PATH'; PROJECT=$2; shift 2 ;;
        --runtime) [ "$#" -ge 2 ] || fail '--runtime requires NAME'; add_runtime "$2"; shift 2 ;;
        --yes) YES=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --quiet) QUIET=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "unknown argument: $1" ;;
    esac
done

SCRIPT=$0
case $SCRIPT in */*) : ;; *) SCRIPT=./$SCRIPT ;; esac
SOURCE=$(CDPATH= cd "$(dirname "$SCRIPT")" && pwd -P)
for skill in $SKILLS; do [ -f "$SOURCE/$skill/SKILL.md" ] || fail "missing source skill: $SOURCE/$skill"; done
[ -n "${HOME:-}" ] || fail 'HOME is not set'
if [ -n "$PROJECT" ]; then
    [ -d "$PROJECT" ] || fail "project path is not a directory: $PROJECT"
    PROJECT=$(CDPATH= cd "$PROJECT" && pwd -P)
fi

runtime_root() {
    case $1 in
        claude) [ -n "$PROJECT" ] && printf '%s/.claude/skills\n' "$PROJECT" || printf '%s/.claude/skills\n' "$HOME" ;;
        agents) [ -n "$PROJECT" ] && printf '%s/.agents/skills\n' "$PROJECT" || printf '%s/.agents/skills\n' "$HOME" ;;
        devin) [ -n "$PROJECT" ] && printf '%s/.devin/skills\n' "$PROJECT" || printf '%s/.config/devin/skills\n' "$HOME" ;;
    esac
}
if [ "$RUNTIME_SET" -eq 0 ]; then
    if [ "$YES" -eq 1 ]; then
        add_runtime all
    elif [ -t 0 ] && [ -t 1 ]; then
        detected=
        for runtime in claude agents devin; do [ -d "$(runtime_root "$runtime")" ] && detected="$detected $runtime"; done
        [ -n "$detected" ] || detected=' claude agents devin'
        printf 'Install for%s? [Y/n] ' "$detected" >/dev/tty
        IFS= read -r answer </dev/tty || answer=n
        case $answer in ''|y|Y|yes|YES) for runtime in $detected; do add_runtime "$runtime"; done ;; *) fail 'installation cancelled' ;; esac
    else
        fail 'non-interactive use requires --runtime NAME or --yes'
    fi
fi
case " $RUNTIMES " in *' agents '*) RUNTIMES=$(printf '%s\n' "$RUNTIMES" | sed 's/ devin//g') ;; esac

is_managed() {
    path=$1 skill=$2 marker=$1/$MARKER
    [ -d "$path" ] && [ ! -L "$path" ] && [ -f "$marker" ] && [ ! -L "$marker" ] && [ ! -x "$marker" ] && [ "$(cat "$marker" 2>/dev/null)" = "$MARKER_TEXT:$skill" ]
}
is_legacy() {
    path=$1 skill=$2
    [ -L "$path" ] || return 1
    target=$(readlink "$path") || return 1
    case $target in /*) resolved=$target ;; *) resolved=$(dirname "$path")/$target ;; esac
    [ -d "$resolved" ] && [ -f "$resolved/SKILL.md" ] && [ "$(basename "$resolved")" = "$skill" ]
}

check_destination() {
    destination=$1 skill=$2
    if [ -L "$destination" ]; then
        is_legacy "$destination" "$skill" || fail "refusing unmanaged link: $destination"
        [ "$YES" -eq 1 ] || fail "legacy link requires --yes: $destination"
    elif [ -e "$destination" ]; then
        is_managed "$destination" "$skill" || fail "refusing unmanaged path: $destination"
    fi
}

if [ "$COMMAND" = doctor ]; then
    bad=0
    for runtime in $RUNTIMES; do
        root=$(runtime_root "$runtime")
        for skill in $SKILLS; do
            destination=$root/$skill
            if is_managed "$destination" "$skill" && [ -f "$destination/SKILL.md" ]; then say "ok: $destination"; else printf 'invalid or missing: %s\n' "$destination" >&2; bad=1; fi
        done
    done
    [ "$bad" -eq 0 ] || exit 1
    exit 0
fi

if [ "$COMMAND" = uninstall ]; then
    for runtime in $RUNTIMES; do
        root=$(runtime_root "$runtime")
        for skill in $SKILLS; do
            destination=$root/$skill
            if [ -e "$destination" ] || [ -L "$destination" ]; then
                is_managed "$destination" "$skill" || fail "refusing unmanaged path: $destination"
                if [ "$DRY_RUN" -eq 1 ]; then say "would remove $destination"; else rm -rf "$destination"; say "removed $destination"; fi
            fi
        done
    done
    exit 0
fi

for runtime in $RUNTIMES; do
    root=$(runtime_root "$runtime")
    for skill in $SKILLS; do check_destination "$root/$skill" "$skill"; done
done
if [ "$DRY_RUN" -eq 1 ]; then
    for runtime in $RUNTIMES; do root=$(runtime_root "$runtime"); for skill in $SKILLS; do say "would install $root/$skill"; done; done
    exit 0
fi

TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/llm-sast-install.XXXXXX") || fail 'cannot create temporary directory'
PLAN=$TMP_ROOT/plan
: > "$PLAN"
cleanup() {
    if [ -f "$PLAN" ]; then while IFS="$TAB" read -r stage destination backup; do [ -z "$stage" ] || rm -rf "$stage"; done < "$PLAN"; fi
    rm -rf "$TMP_ROOT"
}
rollback() {
    [ -n "$ACTIVE" ] && [ -f "$ACTIVE" ] || return 0
    while IFS="$TAB" read -r destination backup; do
        [ -n "$destination" ] || continue
        rm -rf "$destination"
        [ -n "$backup" ] && [ -e "$backup" ] && mv "$backup" "$destination"
    done < "$ACTIVE"
}
trap 'rollback; cleanup' EXIT
trap 'exit 1' HUP INT TERM

index=0
for runtime in $RUNTIMES; do
    root=$(runtime_root "$runtime")
    mkdir -p "$root"
    for skill in $SKILLS; do
        index=$((index + 1)); stage=$root/.llm-sast-stage-$$-$index; destination=$root/$skill; backup=
        if [ -e "$destination" ] || [ -L "$destination" ]; then backup=$root/.llm-sast-backup-$$-$index; fi
        printf '%s\t%s\t%s\n' "$stage" "$destination" "$backup" >> "$PLAN"
        rm -rf "$stage"; mkdir "$stage"; cp -R "$SOURCE/$skill/." "$stage/"
        printf '%s:%s\n' "$MARKER_TEXT" "$skill" > "$stage/$MARKER"; chmod 600 "$stage/$MARKER"
    done
done
ACTIVE=$TMP_ROOT/active
: > "$ACTIVE"
activation_failed=0
while IFS="$TAB" read -r stage destination backup; do
    if [ -n "$backup" ] && ! mv "$destination" "$backup"; then activation_failed=1; break; fi
    printf '%s\t%s\n' "$destination" "$backup" >> "$ACTIVE"
    if ! mv "$stage" "$destination"; then activation_failed=1; break; fi
done < "$PLAN"
if [ "$activation_failed" -eq 1 ]; then trap - EXIT HUP INT TERM; rollback; ACTIVE=; cleanup; fail 'activation failed; previous installation restored'; fi
while IFS="$TAB" read -r destination backup; do [ -z "$backup" ] || rm -rf "$backup" || :; say "installed $destination"; done < "$ACTIVE"
ACTIVE=
trap - EXIT HUP INT TERM
cleanup
