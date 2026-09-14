#!/bin/sh
# Installer / health check for the llm-sast-scanner skills.
#
#   sh install.sh install [agents|claude|all]
#   sh install.sh doctor  [agents|claude|all]
#
# install  symlinks the three skill directories of THIS checkout into the
#          selected runtime root(s): ~/.claude/skills and/or ~/.agents/skills.
#          $HOME must be an existing directory; the runtime roots are created
#          when missing. Every destination is checked before anything is
#          changed, so a refusal during those checks leaves both roots exactly
#          as they were. Roots are then updated one at a time and each is
#          re-verified just before it is touched; should the first update ever
#          change where the second root resolves, install stops before touching
#          it and reports what happened. Existing symlinks and empty directories
#          are replaced; anything else is left alone and reported as an error.
# doctor   verifies that every selected entry is a symlink whose target is the
#          corresponding skill directory of this checkout.
set -eu

usage() {
    printf 'usage: sh install.sh install [agents|claude|all]\n' >&2
    printf '       sh install.sh doctor [agents|claude|all]\n' >&2
    exit 1
}

fail() {
    printf 'error: %s\n' "$1" >&2
    exit 1
}

# Print the physical (symlink-free) path of the existing directory $1.
# cd -P makes ".." follow the real parent, matching what the kernel does.
physical() {
    # shellcheck disable=SC1007  # intentional: neutralise CDPATH for this single cd
    (CDPATH= cd -P "$1" 2>/dev/null && pwd -P)
}

# True when $1 and $2 are the same directory, compared by identity rather than
# by name, so different spellings of one directory (e.g. on a case-insensitive
# filesystem) are recognised.
same_dir() {
    # shellcheck disable=SC3013  # -ef predates POSIX.1-2024 but every sh in use supports it
    [ "$1" -ef "$2" ]
}

# True when $1 and $2 are the same directory entry, compared by inode without
# following symlinks: a differently spelled name for one entry (as on a
# case-insensitive filesystem) matches, a different symlink to the same target
# does not. False when either does not exist. Callers guarantee a common parent
# directory, so the device is implied.
same_entry() {
    { [ -e "$1" ] || [ -L "$1" ]; } && { [ -e "$2" ] || [ -L "$2" ]; } || return 1
    # shellcheck disable=SC2012  # only the inode column is read; the name is never parsed
    a=$(ls -ldi "$1" 2>/dev/null | awk 'NR == 1 { print $1 }')
    # shellcheck disable=SC2012
    b=$(ls -ldi "$2" 2>/dev/null | awk 'NR == 1 { print $1 }')
    [ -n "$a" ] && [ "$a" = "$b" ]
}

# True when directory $1 is $2 or lies anywhere below it. Both are physical
# paths; the ancestors of $1 are compared to $2 by identity.
is_within() {
    case $1 in
        "$2"|"$2"/*) return 0 ;;
    esac
    p=$1
    while :; do
        if same_dir "$p" "$2"; then
            return 0
        fi
        parent=$(dirname "$p")
        [ "$parent" != "$p" ] || return 1
        p=$parent
    done
}

# Print the physical path at which directory $1 exists, or would be created by
# "mkdir -p". Creates nothing. $1 must be absolute. Returns 1 when $1 or one of
# its ancestors exists but is not a directory, 2 when the nearest existing
# ancestor cannot be entered, 3 when its canonical path is not representable
# (command substitution cannot carry a trailing newline), 4 when a component is
# a symlink to a location that does not exist.
would_be() {
    probe=$1
    tail=''
    while [ ! -d "$probe" ]; do
        if [ -e "$probe" ]; then
            return 1
        elif [ -L "$probe" ]; then
            return 4
        fi
        tail="$(basename "$probe")${tail:+/$tail}"
        probe=$(dirname "$probe")
    done
    anc=$probe
    probe=$(physical "$anc") || return 2
    same_dir "$anc" "$probe" || return 3
    [ "$probe" != / ] || [ -z "$tail" ] || probe=''   # avoid "//x" when the ancestor is the filesystem root
    printf '%s%s\n' "$probe" "${tail:+/$tail}"
}

# True when $1 carries a BSD immutable or append-only flag (macOS, FreeBSD),
# which blocks rm/rmdir of or inside it. Field 5 of "ls -ldO" holds the flags
# there; elsewhere ls rejects -O and the test is a no-op. The system ls is used
# so that a GNU ls earlier in PATH cannot silently disable the check.
has_restrictive_flags() {
    # shellcheck disable=SC2012  # only the flags column is read; the name is never parsed
    case $("${system_ls:-ls}" -ldO "$1" 2>/dev/null | awk 'NR == 1 { print $5 }') in
        *appnd*|*chg*) return 0 ;;
    esac
    return 1
}

# Resolve the absolute logical path $1 component by component, following
# symlinks as they are met, and print the first visited component that is a
# skill entry of one of the approved roots given as $2... (a location install is
# about to replace). Existing entries are matched by identity, so a differently
# spelled name on a case-insensitive filesystem counts; entries that do not
# exist yet are matched by name. Prints nothing when no such entry is traversed.
# Components that do not exist yet end the walk: mkdir -p will create them.
traverses_entry() {
    rest=${1#/}
    shift
    walk=/
    thops=0
    while [ -n "$rest" ]; do
        comp=${rest%%/*}
        if [ "$rest" = "$comp" ]; then rest=''; else rest=${rest#*/}; fi
        case $comp in
            ''|.) continue ;;
            ..) walk=$(dirname "$walk"); continue ;;
        esac
        here=${walk%/}/$comp
        for other in "$@"; do
            if same_dir "$walk" "$other"; then
                for skill in $skills; do
                    if [ "$comp" = "$skill" ] || same_entry "$here" "$other/$skill"; then
                        printf '%s\n' "$here"
                        return 0
                    fi
                done
            fi
        done
        if [ -L "$here" ]; then
            thops=$((thops + 1))
            [ "$thops" -le 40 ] || return 1
            link=$(readlink "$here") || return 1
            case $link in
                /*) walk=/; rest="${link#/}${rest:+/$rest}" ;;
                *) rest="$link${rest:+/$rest}" ;;
            esac
        elif [ -d "$here" ]; then
            walk=$here
        else
            return 1
        fi
    done
    return 1
}

system_ls='ls'
[ ! -x /bin/ls ] || system_ls=/bin/ls

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
case $1 in
    install|doctor) action=$1 ;;
    *) usage ;;
esac

target=all
if [ "$#" -eq 2 ]; then
    case $2 in
        agents|claude|all) target=$2 ;;
        *) usage ;;
    esac
fi

skills='llm-sast-scanner llm-sast-scanner-convergence-loop llm-sast-scanner-full-scan-loop'

# Locate this script, following symlinks, so it may be invoked through a
# symlink placed anywhere (e.g. ~/bin/sast-install -> <checkout>/install.sh).
script=$0
case $script in
    /*) : ;;
    *) script=./$script ;;   # also shields dirname/readlink from a leading '-'
esac
hops=0
while [ -L "$script" ]; do
    hops=$((hops + 1))
    [ "$hops" -le 40 ] || fail "too many levels of symbolic links: $0"
    link=$(readlink "$script") || fail "cannot read symlink: $script"
    case $link in
        /*) script=$link ;;
        *) script=$(dirname "$script")/$link ;;
    esac
done
script_dir=$(physical "$(dirname "$script")") \
    || fail "cannot resolve the directory containing $0"

repo_root=$(git -C "$script_dir" rev-parse --show-toplevel 2>/dev/null) && [ -n "$repo_root" ] \
    || fail 'install.sh is not inside a Git checkout'

for skill in $skills; do
    [ -r "$repo_root/$skill/SKILL.md" ] || fail "missing or unreadable: $repo_root/$skill/SKILL.md"
done

[ -n "${HOME:-}" ] || fail 'HOME is not set'

case $target in
    agents) suffixes='.agents/skills' ;;
    claude) suffixes='.claude/skills' ;;
    all) suffixes='.claude/skills .agents/skills' ;;
    *) fail "unknown target: $target" ;;
esac

# ---------------------------------------------------------------- install --
if [ "$action" = install ]; then
    # Whatever the caller's umask, everything this script creates must stay
    # usable by its owner (macOS applies the mode bits to symlinks too).
    mask=$(umask -S)
    umask "u=rwx,${mask#*,}"

    home_real=$(physical "$HOME") || fail "HOME ($HOME) is not an accessible directory"
    # Command substitution drops trailing newlines; make sure home_real is HOME.
    same_dir "$HOME" "$home_real" || fail "HOME ($HOME) cannot be used: its canonical path is not representable"
    home_real=${home_real%/}                  # HOME=/ must not yield //.claude

    # Pre-flight: validate everything before touching anything. The approved
    # physical location of each root is kept in the positional parameters.
    set --
    for suffix in $suffixes; do
        root_real=$(would_be "$home_real/$suffix") || case $? in
            2) fail "cannot access $HOME/$suffix (or one of its parents): permission denied" ;;
            3) fail "$HOME/$suffix (or one of its parents) cannot be used: its canonical path is not representable" ;;
            4) fail "$HOME/$suffix (or one of its parents) is a symlink to a location that does not exist; create the target or fix the symlink and re-run" ;;
            *) fail "$HOME/$suffix (or one of its parents) exists but is not a directory" ;;
        esac
        set -- "$@" "$root_real"
        anchor=$root_real                     # nearest existing ancestor of the root
        while [ ! -d "$anchor" ]; do
            anchor=$(dirname "$anchor")
        done
        if is_within "$anchor" "$repo_root"; then
            fail "runtime root $HOME/$suffix lies inside the checkout $repo_root; refusing to install into the checkout itself"
        fi
        [ -w "$anchor" ] || fail "runtime root $HOME/$suffix is not writable ($anchor)"
        if [ -d "$root_real" ] && has_restrictive_flags "$root_real"; then
            fail "runtime root $HOME/$suffix is append-only or immutable ($root_real); clear its flags and re-run"
        fi
        for skill in $skills; do
            destination="$root_real/$skill"
            if [ -L "$destination" ]; then
                # an existing symlink is ours to replace, unless its own flags forbid it
                if has_restrictive_flags "$destination"; then
                    fail "cannot replace symlink $destination (immutable or append-only); clear its flags (chflags -h) or move it away and re-run"
                fi
            elif [ -d "$destination" ]; then
                if is_within "$repo_root" "$destination"; then
                    fail "$destination is this checkout (or contains it); clone the repository outside $HOME/$suffix and re-run"
                fi
                entries=$(ls -Aq "$destination" 2>/dev/null) \
                    || fail "cannot read directory $destination; fix its permissions or move it away and re-run"
                [ -z "$entries" ] \
                    || fail "refusing to replace non-empty directory $destination; move it away and re-run"
                if has_restrictive_flags "$destination"; then
                    fail "cannot remove directory $destination (immutable or append-only); clear its flags or move it away and re-run"
                fi
            elif [ -e "$destination" ]; then
                fail "refusing to replace $destination: not a symlink; move it away and re-run"
            fi
        done
    done

    # No root may resolve through an entry that install is about to replace;
    # replacing it would silently redirect that root. The root's path is walked
    # component by component (following symlinks), and each visited component is
    # compared by identity against the entries of every selected root.
    for suffix in $suffixes; do
        hit=$(traverses_entry "$home_real/$suffix" "$@") || true
        [ -z "$hit" ] || fail "runtime root $HOME/$suffix resolves through $hit, which install would replace; fix that symlink and re-run"
    done

    for suffix in $suffixes; do
        approved=$1
        shift
        root="$home_real/$suffix"
        now=$(would_be "$root") && [ "$now" = "$approved" ] \
            || fail "runtime root $HOME/$suffix no longer resolves to $approved; an earlier step changed something it passes through, stopping"
        mkdir -p "$root"
        root_real=$(physical "$root") && [ "$root_real" = "$approved" ] \
            || fail "runtime root $HOME/$suffix resolved to ${root_real:-nothing} instead of $approved after creation, stopping"
        [ -w "$root_real" ] || fail "runtime root $HOME/$suffix is not writable after creation ($root_real)"
        for skill in $skills; do
            destination="$root_real/$skill"
            if [ -L "$destination" ]; then
                rm -f "$destination" || fail "cannot remove symlink $destination (check ACLs or flags on it and on $root_real), stopping"
            elif [ -d "$destination" ]; then
                rmdir "$destination" || fail "cannot remove directory $destination (check ACLs, flags, or whether it is a mount point), stopping"
            fi
            ln -s "$repo_root/$skill" "$destination" || fail "cannot create symlink $destination, stopping"
        done
    done
    exit 0
fi

# ----------------------------------------------------------------- doctor --
upstream=none
if upstream_ref=$(git -C "$repo_root" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null); then
    upstream=$upstream_ref
fi

remote_name=none
remote_url=none
branch_remote=''
if current_branch=$(git -C "$repo_root" rev-parse --abbrev-ref HEAD 2>/dev/null) && [ "$current_branch" != HEAD ]; then
    branch_remote=$(git -C "$repo_root" config --get "branch.$current_branch.remote" 2>/dev/null || true)
fi
if [ -n "$branch_remote" ] && [ "$branch_remote" != . ]; then
    if url=$(git -C "$repo_root" remote get-url "$branch_remote" 2>/dev/null); then
        remote_name=$branch_remote
        remote_url=$url
    fi
fi
if [ "$remote_url" = none ]; then
    if url=$(git -C "$repo_root" remote get-url origin 2>/dev/null); then
        remote_name=origin
        remote_url=$url
    fi
fi

printf 'repository root: %s\n' "$repo_root"
printf 'upstream: %s\n' "$upstream"
printf 'remote: %s\n' "$remote_name"
printf 'remote url: %s\n' "$remote_url"

invalid=0
for suffix in $suffixes; do
    root="$HOME/$suffix"
    for skill in $skills; do
        destination="$root/$skill"
        expected="$repo_root/$skill"
        if [ ! -L "$destination" ] \
            || ! link_target=$(readlink "$destination") \
            || [ "$link_target" != "$expected" ] \
            || [ ! -r "$expected/SKILL.md" ]; then
            printf 'invalid: %s\n' "$destination" >&2
            invalid=1
            continue
        fi
        printf 'ok: %s\n' "$destination"
    done
done

exit "$invalid"
