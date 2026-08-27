#!/bin/sh
set -eu

usage() {
    printf 'usage: sh install.sh install [agents|claude|all]\n' >&2
    printf '       sh install.sh doctor [agents|claude|all]\n' >&2
    exit 1
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
case $1 in
    install|doctor) command=$1 ;;
    *) usage ;;
esac

target=all
if [ "$#" -eq 2 ]; then
    case $2 in
        agents|claude|all) target=$2 ;;
        *) usage ;;
    esac
fi

script=$0
case $script in
    */*) : ;;
    *) script=./$script ;;
esac
script_dir=$(CDPATH= cd "$(dirname "$script")" && pwd -P)

if ! repo_root=$(git -C "$script_dir" rev-parse --show-toplevel 2>/dev/null) || [ -z "$repo_root" ]; then
    printf 'error: install.sh is not inside a Git checkout\n' >&2
    exit 1
fi

for skill in \
    llm-sast-scanner \
    llm-sast-scanner-convergence-loop \
    llm-sast-scanner-full-scan-loop
do
    [ -f "$repo_root/$skill/SKILL.md" ] || {
        printf 'missing: %s/SKILL.md\n' "$repo_root/$skill" >&2
        exit 1
    }
done

upstream='none'
branch_remote=''

if upstream_ref=$(git -C "$repo_root" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null); then
    upstream=$upstream_ref
fi

if current_branch=$(git -C "$repo_root" rev-parse --abbrev-ref HEAD 2>/dev/null) && [ "$current_branch" != 'HEAD' ]; then
    branch_remote=$(git -C "$repo_root" config --get "branch.$current_branch.remote" 2>/dev/null || true)
fi

remote_name=''
remote_url=''

if [ -n "$branch_remote" ] && [ "$branch_remote" != '.' ]; then
    remote_name=$branch_remote
    remote_url=$(git -C "$repo_root" remote get-url "$branch_remote" 2>/dev/null || true)
fi

if [ -z "$remote_url" ]; then
    if remote_url=$(git -C "$repo_root" remote get-url origin 2>/dev/null); then
        remote_name=origin
    else
        printf 'error: checkout has no configured remote URL\n' >&2
        exit 1
    fi
fi

[ -n "${HOME:-}" ] || {
    printf 'HOME is not set\n' >&2
    exit 1
}

roots=
case $target in
    agents) roots="$HOME/.agents/skills" ;;
    claude) roots="$HOME/.claude/skills" ;;
    all) roots="$HOME/.claude/skills $HOME/.agents/skills" ;;
esac

if [ "$command" = install ]; then
    for root in $roots; do
        mkdir -p "$root"
        for skill in \
            llm-sast-scanner \
            llm-sast-scanner-convergence-loop \
            llm-sast-scanner-full-scan-loop
        do
            destination="$root/$skill"
            source_dir="$repo_root/$skill"
            if [ -e "$destination" ] || [ -L "$destination" ]; then
                rm -rf "$destination"
            fi
            ln -s "$source_dir" "$destination"
        done
    done
    exit 0
fi

printf 'repository root: %s\n' "$repo_root"
printf 'upstream: %s\n' "$upstream"
printf 'remote: %s\n' "$remote_name"
printf 'remote url: %s\n' "$remote_url"

invalid=0
for root in $roots; do
    for skill in \
        llm-sast-scanner \
        llm-sast-scanner-convergence-loop \
        llm-sast-scanner-full-scan-loop
    do
        destination="$root/$skill"
        expected="$repo_root/$skill"
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
