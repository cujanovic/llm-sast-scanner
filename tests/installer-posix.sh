#!/bin/sh
set -eu

TEST_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
REPO=$(CDPATH= cd "$TEST_DIR/.." && pwd -P)
SKILLS='llm-sast-scanner llm-sast-scanner-convergence-loop llm-sast-scanner-full-scan-loop'
MARKER=.llm-sast-scanner-managed
MARKER_TEXT=llm-sast-scanner-managed-v1
PASS=0
FAIL=0
OUTPUT=
STATUS=0
SANDBOX=

assert() { "$@" || { printf 'assertion failed: %s\n' "$*" >&2; return 1; }; }
contains() { case $1 in *"$2"*) return 0 ;; *) return 1 ;; esac; }
run() { set +e; OUTPUT=$(sh "$INSTALLER" "$@" 2>&1); STATUS=$?; set -e; }
run_bootstrap() { set +e; OUTPUT=$(sh "$REPO/bootstrap.sh" "$@" 2>&1); STATUS=$?; set -e; }
new_sandbox() {
    [ -z "$SANDBOX" ] || rm -rf "$SANDBOX"
    SANDBOX=$(mktemp -d "${TMPDIR:-/tmp}/llm sast tests.XXXXXX")
    HOME=$SANDBOX/'home with spaces'; TMPDIR=$SANDBOX/tmp; export HOME TMPDIR
    mkdir -p "$HOME" "$TMPDIR"
    SOURCE=$SANDBOX/'source with spaces'; mkdir "$SOURCE"; cp "$REPO/install.sh" "$SOURCE/install.sh"
    for skill in $SKILLS; do mkdir "$SOURCE/$skill"; printf '# fixture\nold\n' > "$SOURCE/$skill/SKILL.md"; done
    INSTALLER=$SOURCE/install.sh
}
cleanup() { [ -z "$SANDBOX" ] || rm -rf "$SANDBOX"; }
trap cleanup EXIT HUP INT TERM
case_run() {
    name=$1; shift
    if ( "$@" ); then PASS=$((PASS + 1)); printf 'ok - %s\n' "$name"
    else FAIL=$((FAIL + 1)); printf 'not ok - %s\n' "$name" >&2
    fi
}

case_global_project_dedup_spaces() {
    new_sandbox
    run install --runtime all --yes; assert test "$STATUS" -eq 0
    for root in "$HOME/.claude/skills" "$HOME/.agents/skills"; do for skill in $SKILLS; do
        assert test -f "$root/$skill/SKILL.md"; assert test -f "$root/$skill/$MARKER"; assert test ! -x "$root/$skill/$MARKER"
        assert test "$(cat "$root/$skill/$MARKER")" = "$MARKER_TEXT:$skill"
    done; done
    assert test ! -e "$HOME/.config/devin/skills"
    project=$SANDBOX/'project path with spaces'; mkdir "$project"
    run --project "$project" --runtime devin; assert test "$STATUS" -eq 0
    assert test -f "$project/.devin/skills/llm-sast-scanner/SKILL.md"
}
case_conflicts_and_legacy() {
    new_sandbox
    mkdir -p "$HOME/.agents/skills/llm-sast-scanner"; printf unrelated > "$HOME/.agents/skills/llm-sast-scanner/file"
    run --runtime agents; assert test "$STATUS" -ne 0; assert contains "$OUTPUT" 'unmanaged'
    rm -rf "$HOME/.agents"
    legacy=$SANDBOX/legacy; mkdir "$legacy"
    for skill in $SKILLS; do mkdir "$legacy/$skill"; printf legacy > "$legacy/$skill/SKILL.md"; done
    mkdir -p "$HOME/.agents/skills"
    for skill in $SKILLS; do ln -s "$legacy/$skill" "$HOME/.agents/skills/$skill"; done
    run --runtime agents; assert test "$STATUS" -ne 0; assert contains "$OUTPUT" 'requires --yes'
    run --runtime agents --yes; assert test "$STATUS" -eq 0
    assert test ! -L "$HOME/.agents/skills/llm-sast-scanner"; assert test -f "$HOME/.agents/skills/llm-sast-scanner/$MARKER"
}
case_rerun_doctor_uninstall() {
    new_sandbox
    run --runtime agents; assert test "$STATUS" -eq 0
    run --runtime agents --quiet; assert test "$STATUS" -eq 0; assert test -z "$OUTPUT"
    printf '# fixture\nnew\n' > "$SOURCE/llm-sast-scanner/SKILL.md"
    run install --runtime agents; assert test "$STATUS" -eq 0
    assert contains "$(cat "$HOME/.agents/skills/llm-sast-scanner/SKILL.md")" new
    run doctor --runtime agents; assert test "$STATUS" -eq 0; assert contains "$OUTPUT" 'ok:'
    run uninstall --runtime agents --dry-run; assert test "$STATUS" -eq 0; assert test -d "$HOME/.agents/skills/llm-sast-scanner"
    run uninstall --runtime agents; assert test "$STATUS" -eq 0; assert test ! -e "$HOME/.agents/skills/llm-sast-scanner"
}
case_doctor_and_safe_uninstall() {
    new_sandbox
    run --runtime claude; assert test "$STATUS" -eq 0
    rm "$HOME/.claude/skills/llm-sast-scanner/$MARKER"
    run doctor --runtime claude; assert test "$STATUS" -ne 0
    run uninstall --runtime claude; assert test "$STATUS" -ne 0; assert test -d "$HOME/.claude/skills/llm-sast-scanner"
}
case_forged_markers() {
    new_sandbox
    run --runtime agents; assert test "$STATUS" -eq 0
    path=$HOME/.agents/skills/llm-sast-scanner
    for content in "$MARKER_TEXT" "$MARKER_TEXT:llm-sast-scanner-convergence-loop"; do
        printf '%s\n' "$content" > "$path/$MARKER"
        run doctor --runtime agents; assert test "$STATUS" -ne 0
        run install --runtime agents; assert test "$STATUS" -ne 0; assert contains "$OUTPUT" 'unmanaged'
        run uninstall --runtime agents; assert test "$STATUS" -ne 0; assert test -d "$path"
    done
}
case_dry_run() {
    new_sandbox
    run --runtime agents --dry-run; assert test "$STATUS" -eq 0; assert contains "$OUTPUT" 'would install'
    assert test ! -e "$HOME/.agents"
}
case_mocked_bootstrap() {
    new_sandbox
    archive_root=$SANDBOX/archive/llm-sast-scanner-main; mkdir -p "$archive_root"
    cp "$SOURCE/install.sh" "$archive_root/install.sh"; cp "$REPO/install.ps1" "$archive_root/install.ps1"
    for skill in $SKILLS; do cp -R "$SOURCE/$skill" "$archive_root/$skill"; done
    archive=$SANDBOX/source.tar.gz; (cd "$SANDBOX/archive" && tar -czf "$archive" llm-sast-scanner-main)
    mock=$SANDBOX/bin; mkdir "$mock"
    cat > "$mock/curl" <<'MOCK'
#!/bin/sh
out=
while [ "$#" -gt 0 ]; do case $1 in -o) out=$2; shift 2 ;; *) shift ;; esac; done
cp "$MOCK_ARCHIVE" "$out"
MOCK
    chmod +x "$mock/curl"; MOCK_ARCHIVE=$archive; export MOCK_ARCHIVE
    old_path=$PATH; PATH=$mock:/usr/bin:/bin; export PATH
    run_bootstrap --runtime agents
    PATH=$old_path; export PATH
    assert test "$STATUS" -eq 0; assert test -f "$HOME/.agents/skills/llm-sast-scanner/$MARKER"
}

case_run 'global/project destinations, dedup, spaces' case_global_project_dedup_spaces
case_run 'unmanaged conflict and legacy migration' case_conflicts_and_legacy
case_run 'idempotent rerun/update, doctor, uninstall' case_rerun_doctor_uninstall
case_run 'doctor and safe uninstall' case_doctor_and_safe_uninstall
case_run 'forged marker refusal' case_forged_markers
case_run 'dry run' case_dry_run
case_run 'mocked bootstrap' case_mocked_bootstrap
printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
