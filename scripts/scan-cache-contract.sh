#!/usr/bin/env bash
set -euo pipefail
umask 077

SYMLINK_MAX_HOPS=40
SNAPSHOT_TEMP_DIRS=()
RESOLVE_SYMLINK_RESULT=""

die() { printf 'scan-cache-contract: %s\n' "$*" >&2; exit 1; }
sha256_file() { shasum -a 256 -- "$1" | awk '{print $1}'; }
sha256_stream() { shasum -a 256 | awk '{print $1}'; }
base64_path() { base64 | tr -d '\r\n'; }
is_hex64() { [[ $1 =~ ^[0-9a-f]{64}$ ]]; }

snapshot_temp_register() {
  local dir=$1
  [ -n "$dir" ] && SNAPSHOT_TEMP_DIRS+=("$dir")
}

snapshot_temp_cleanup() {
  local d
  for d in "${SNAPSHOT_TEMP_DIRS[@]}"; do
    if [ -n "$d" ] && [ -d "$d" ]; then
      chmod -R u+rwX "$d" 2>/dev/null || true
      rm -rf "$d"
    fi
  done
  SNAPSHOT_TEMP_DIRS=()
}

snapshot_temp_trap_on() {
  trap snapshot_temp_cleanup EXIT INT TERM
}

snapshot_temp_trap_off() {
  snapshot_temp_cleanup
  trap - EXIT INT TERM
}

abs_path() {
  local p=$1 dir base
  dir="$(cd "$(dirname -- "$p")" && pwd -P)"
  base="$(basename -- "$p")"
  printf '%s/%s' "$dir" "$base"
}

validate_dir() {
  local label=$1 path=$2
  [ -n "$path" ] || die "$label path required"
  [ -d "$path" ] || die "$label is not a directory: $path"
}

validate_cleanup_path() {
  local cache=$1 path=$2
  local cache_real path_real
  cache_real="$(abs_path "$cache")"
  path_real="$(abs_path "$path")"
  case "$path_real" in
    "$cache_real"/source-snapshot-*|"$cache_real"/.snapshot-*)
      return 0
      ;;
  esac
  die "unsafe cleanup path: $path"
}

resolve_symlink_absolute() {
  local path=$1
  local hops=0 target dir seen="" canon
  RESOLVE_SYMLINK_RESULT=""
  while [ -L "$path" ]; do
    hops=$((hops + 1))
    if [ "$hops" -gt "$SYMLINK_MAX_HOPS" ]; then
      printf 'scan-cache-contract: symlink hop limit exceeded\n' >&2
      return 1
    fi
    canon="$(abs_path "$path")"
    case $'\n'"$seen" in
      *$'\n'"$canon"$'\n'*)
        printf 'scan-cache-contract: cyclic symlink rejected\n' >&2
        return 1
        ;;
    esac
    seen="${seen}${canon}"$'\n'
    target="$(readlink "$path")"
    if [ "${target#/}" = "$target" ]; then
      dir="$(cd "$(dirname -- "$path")" && pwd -P)"
      path="$dir/$target"
    else
      path="$target"
    fi
    if [ -L "$path" ]; then
      dir="$(cd "$(dirname -- "$path")" 2>/dev/null && pwd -P)" || return 1
      path="$dir/$(basename -- "$path")"
    fi
  done
  if [ -d "$path" ]; then
    RESOLVE_SYMLINK_RESULT="$(cd "$path" && pwd -P)"
  else
    dir="$(cd "$(dirname -- "$path")" && pwd -P)"
    RESOLVE_SYMLINK_RESULT="$dir/$(basename -- "$path")"
  fi
  return 0
}

symlink_escapes_target() {
  local target=$1 rel=$2
  local root resolved
  [ -L "$target/$rel" ] || return 1
  root="$(cd "$target" && pwd -P)"
  resolve_symlink_absolute "$target/$rel" || return 2
  resolved="$RESOLVE_SYMLINK_RESULT"
  case "$resolved" in
    "$root"|"$root"/*) return 1 ;;
    *) return 0 ;;
  esac
}

should_exclude_path() {
  local rel=$1
  local base="${rel##*/}"

  if [ "$base" = ".git" ]; then
    return 0
  fi

  case "$base" in
    package-lock.json|yarn.lock|pnpm-lock.yaml|poetry.lock|Gemfile.lock|go.sum|Cargo.lock)
      return 0
      ;;
    sast_report-*.md)
      return 0
      ;;
  esac

  case "$rel" in
    .llm-sast-scanner-cache|.llm-sast-scanner-cache/*|.llm-sast-scanner-cache-*|.llm-sast-scanner-cache-*/*)
      return 0
      ;;
  esac

  case "$rel" in
    *.min.js|*.bundle.js|*.map|*.png|*.jpg|*.jpeg|*.gif|*.webp|*.ico|*.pdf|*.zip|*.gz|*.jar|*.woff|*.woff2|*.ttf|*.mp4|*.so|*.dylib|*.dll|*.exe|*.wasm)
      return 0
      ;;
  esac

  return 1
}

is_binary_file() {
  local file=$1
  [ -s "$file" ] || return 1
  grep -Iq '' -- "$file" 2>/dev/null || return 0
  return 1
}

is_symlink_to_directory() {
  local path=$1
  [ -L "$path" ] || return 1
  [ -d "$path" ] && ! [ -f "$path" ]
}

manifest_entry_lines() {
  local tree_path=$1 source_path=$2
  if [ -L "$source_path" ] && is_symlink_to_directory "$source_path"; then
    printf '0'
  elif [ -f "$tree_path" ]; then
    wc -l < "$tree_path" | tr -d ' '
  else
    printf '0'
  fi
}

manifest_entry_digest() {
  local tree_path=$1 source_path=$2
  if [ -L "$source_path" ]; then
    local link_target content_digest
    link_target="$(readlink "$source_path")"
    if is_symlink_to_directory "$source_path"; then
      { printf 'symlink-dir-v1\n'; printf '%s\n' "$link_target"; } | sha256_stream
    else
      if [ -f "$source_path" ] && [ -r "$source_path" ]; then
        content_digest="$(sha256_file "$source_path")"
      else
        content_digest="$(printf 'unreadable' | sha256_stream)"
      fi
      { printf 'symlink-v1\n'; printf '%s\n' "$link_target"; printf '%s\n' "$content_digest"; } | sha256_stream
    fi
  else
    sha256_file "$tree_path"
  fi
}

manifest_tree_entry_lines() {
  manifest_entry_lines "$1" "$1"
}

manifest_tree_entry_digest() {
  manifest_entry_digest "$1" "$1"
}

copy_enumerated_paths() {
  local source_root=$1 tree_root=$2 paths_nul=$3
  while IFS= read -r -d '' rel; do
    local src="$source_root/$rel" dest="$tree_root/$rel"
    mkdir -p "$(dirname -- "$dest")"
    if [ -L "$src" ]; then
      ln -s "$(readlink "$src")" "$dest"
    else
      cp -p "$src" "$dest"
    fi
  done < "$paths_nul"
}

enumerate_tree_paths() {
  local tree_root=$1 out=$2
  : > "$out"
  while IFS= read -r -d '' raw; do
    local rel="${raw#"$tree_root"/}"
    if [ "${rel#./}" != "$rel" ]; then
      rel="${rel#./}"
    fi
    [ -n "$rel" ] || continue
    printf '%s\0' "$rel" >> "$out"
  done < <(
    find "$tree_root" \( -type f -o -type l \) -print0 2>/dev/null
  )
}

build_manifest_from_tree() {
  local tree_root=$1 manifest_out=$2
  local paths_nul="${manifest_out}.paths.nul"
  local manifest_unsorted="${manifest_out}.unsorted"

  enumerate_tree_paths "$tree_root" "$paths_nul"
  : > "$manifest_unsorted"
  if [ -s "$paths_nul" ]; then
    while IFS= read -r -d '' rel; do
      local encoded lines digest
      encoded="$(printf '%s' "$rel" | base64_path)"
      lines="$(manifest_tree_entry_lines "$tree_root/$rel")"
      digest="$(manifest_tree_entry_digest "$tree_root/$rel")"
      printf '%s\t%s\t%s\n' "$encoded" "$lines" "$digest" >> "$manifest_unsorted"
    done < "$paths_nul"
  fi
  LC_ALL=C sort -o "$manifest_out" "$manifest_unsorted"
  rm -f "$paths_nul" "$manifest_unsorted"
}

compute_fingerprint_from_manifest() {
  local manifest=$1
  { printf 'source-fingerprint-v2\n'; cat "$manifest"; } | sha256_stream
}

manifests_match() {
  cmp -s "$1" "$2"
}

enumerate_paths() {
  local target=$1 out=$2
  : > "$out"
  while IFS= read -r -d '' raw; do
    local rel=$raw
    if [ "${rel#./}" != "$rel" ]; then
      rel="${rel#./}"
    fi
    should_exclude_path "$rel" && continue
    esc=1
    if symlink_escapes_target "$target" "$rel"; then
      esc=0
    else
      esc=$?
    fi
    if [ "$esc" -eq 0 ]; then
      die "external symlink rejected: $rel"
    elif [ "$esc" -eq 2 ]; then
      exit 1
    fi
    if [ -f "$target/$rel" ] && is_binary_file "$target/$rel"; then
      die "binary file rejected: $rel"
    fi
    printf '%s\0' "$rel" >> "$out"
  done < <(
    cd "$target"
    find . \
      \( -type d \( -name .git -o -name '.llm-sast-scanner-cache*' -o \
        -name node_modules -o -name vendor -o -name third_party -o \
        -name dist -o -name build -o -name out -o -name coverage \) -prune \) -o \
      \( -type f -o -type l \) -print0
  )
}

build_candidate() {
  local target=$1 candidate_dir=$2
  local paths_nul="$candidate_dir/paths.nul"
  local manifest_unsorted="$candidate_dir/manifest.unsorted"
  local manifest_sorted="$candidate_dir/manifest.sorted"
  local fingerprint=""

  mkdir -p "$candidate_dir/tree"
  enumerate_paths "$target" "$paths_nul"

  if [ ! -s "$paths_nul" ]; then
    : > "$manifest_unsorted"
  else
    copy_enumerated_paths "$target" "$candidate_dir/tree" "$paths_nul"

    : > "$manifest_unsorted"
    while IFS= read -r -d '' rel; do
      local encoded lines digest
      encoded="$(printf '%s' "$rel" | base64_path)"
      lines="$(manifest_entry_lines "$candidate_dir/tree/$rel" "$target/$rel")"
      digest="$(manifest_entry_digest "$candidate_dir/tree/$rel" "$target/$rel")"
      printf '%s\t%s\t%s\n' "$encoded" "$lines" "$digest" >> "$manifest_unsorted"
    done < "$paths_nul"
  fi

  LC_ALL=C sort -o "$manifest_sorted" "$manifest_unsorted"
  fingerprint="$(compute_fingerprint_from_manifest "$manifest_sorted")"
  printf '%s' "$fingerprint" >"$candidate_dir/fingerprint.txt"
}

make_tree_readonly() {
  local tree_root=$1
  find "$tree_root" -type f -exec chmod 400 {} +
  find "$tree_root" -type l -exec chmod -h 400 {} +
  find "$tree_root" -type d -exec chmod 500 {} +
  chmod 500 "$tree_root"
}

published_snapshot_valid() {
  local published=$1 expected_fp=$2 candidate_dir=$3
  local recomputed="$candidate_dir/recomputed.manifest"
  [ -d "$published" ] || return 1
  [ -f "$published/.snapshot-complete" ] || return 1
  [ -f "$published/source-fingerprint.txt" ] || return 1
  [ -f "$published/scope-manifest.b64.tsv" ] || return 1
  [ -d "$published/tree" ] || return 1
  [ "$(tr -d '\n' <"$published/source-fingerprint.txt")" = "$expected_fp" ] || return 1
  manifests_match "$published/scope-manifest.b64.tsv" "$candidate_dir/manifest.sorted" || return 1
  build_manifest_from_tree "$published/tree" "$recomputed"
  manifests_match "$published/scope-manifest.b64.tsv" "$recomputed" || return 1
  [ "$(compute_fingerprint_from_manifest "$recomputed")" = "$expected_fp" ] || return 1
  return 0
}

remove_superseded_snapshots() {
  local cache=$1 keep_fp=$2
  local entry keep_dir keep_real entry_real
  keep_dir="$cache/source-snapshot-$keep_fp"
  keep_real="$(abs_path "$keep_dir")"
  shopt -s nullglob
  for entry in "$cache"/source-snapshot-*; do
    [ -d "$entry" ] || continue
    entry_real="$(abs_path "$entry")"
    [ "$entry_real" = "$keep_real" ] && continue
    validate_cleanup_path "$cache" "$entry"
    chmod -R u+rwX "$entry" 2>/dev/null || true
    rm -rf "$entry"
  done
  shopt -u nullglob
}

commit_snapshot_pointer() {
  local cache=$1 published=$2
  local tmp_pointer
  tmp_pointer="$(mktemp "$cache/.snapshot-current.XXXXXX")"
  printf '%s\n' "$(abs_path "$published")" >"$tmp_pointer"
  mv "$tmp_pointer" "$cache/snapshot-current"
}

publish_new_snapshot() {
  local cache=$1 fp=$2 dir_a=$3
  local published="$cache/source-snapshot-$fp"
  if [ -e "$published" ]; then
    die "existing snapshot directory invalid: remove manually and retry: $published"
  fi
  mv "$dir_a" "$published"
  mv "$published/manifest.sorted" "$published/scope-manifest.b64.tsv"
  rm -f "$published/manifest.unsorted" "$published/paths.nul" "$published/fingerprint.txt"
  printf '%s\n' "$fp" >"$published/source-fingerprint.txt"
  : >"$published/.snapshot-complete"
  chmod 700 "$published"
  make_tree_readonly "$published/tree"
  commit_snapshot_pointer "$cache" "$published"
  remove_superseded_snapshots "$cache" "$fp"
  printf 'SNAPSHOT_ROOT=%s/tree\n' "$(abs_path "$published")"
  printf 'SOURCE_FINGERPRINT=%s\n' "$fp"
}

snapshot_prepare() {
  local target="" cache=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --target)
        target=$2
        shift 2
        ;;
      --cache)
        cache=$2
        shift 2
        ;;
      *)
        die "unknown snapshot prepare argument: $1"
        ;;
    esac
  done
  validate_dir target "$target"
  [ -n "$cache" ] || die "cache path required"
  mkdir -p "$cache"
  chmod 700 "$cache"
  [ -d "$cache" ] || die "cache is not a directory: $cache"

  snapshot_temp_trap_on
  local attempt=0 fp_a="" fp_b="" dir_a="" dir_b=""
  while [ "$attempt" -lt 3 ]; do
    dir_a="$(mktemp -d "$cache/.snapshot-candidate.XXXXXX")"
    snapshot_temp_register "$dir_a"
    dir_b="$(mktemp -d "$cache/.snapshot-candidate.XXXXXX")"
    snapshot_temp_register "$dir_b"
    build_candidate "$target" "$dir_a"
    build_candidate "$target" "$dir_b"
    fp_a="$(<"$dir_a/fingerprint.txt")"
    fp_b="$(<"$dir_b/fingerprint.txt")"

    if [ "$fp_a" = "$fp_b" ] && manifests_match "$dir_a/manifest.sorted" "$dir_b/manifest.sorted"; then
      break
    fi

    rm -rf "$dir_a" "$dir_b"
    dir_a=""
    dir_b=""
    attempt=$((attempt + 1))
  done

  if [ -z "$dir_a" ] || [ -z "$dir_b" ]; then
    die "live tree unstable after 3 attempts"
  fi

  is_hex64 "$fp_a" || die "invalid fingerprint computed"

  local published="$cache/source-snapshot-$fp_a"
  rm -rf "$dir_b"
  dir_b=""

  if [ -d "$published" ]; then
    if published_snapshot_valid "$published" "$fp_a" "$dir_a"; then
      rm -rf "$dir_a"
      commit_snapshot_pointer "$cache" "$published"
      remove_superseded_snapshots "$cache" "$fp_a"
      cache_invalidate_stale_preamble "$cache" "$fp_a"
      snapshot_temp_trap_off
      printf 'SNAPSHOT_ROOT=%s/tree\n' "$(abs_path "$published")"
      printf 'SOURCE_FINGERPRINT=%s\n' "$fp_a"
      return 0
    fi
    die "existing snapshot directory invalid: remove manually and retry: $published"
  fi

  publish_new_snapshot "$cache" "$fp_a" "$dir_a"
  cache_invalidate_stale_preamble "$cache" "$fp_a"
  snapshot_temp_trap_off
}

snapshot_verify() {
  local target="" cache=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --target)
        target=$2
        shift 2
        ;;
      --cache)
        cache=$2
        shift 2
        ;;
      *)
        die "unknown snapshot verify argument: $1"
        ;;
    esac
  done
  validate_dir target "$target"
  [ -n "$cache" ] || die "cache path required"
  [ -d "$cache" ] || die "cache is not a directory: $cache"

  local published expected_fp fp_a fp_b dir_a dir_b
  published="$(tr -d '\n' <"$cache/snapshot-current")"
  [ -d "$published" ] || die "snapshot verify failed: invalid snapshot pointer"
  validate_cleanup_path "$cache" "$published"
  [ -f "$published/.snapshot-complete" ] || die "snapshot verify failed: missing completion marker"
  [ -f "$published/source-fingerprint.txt" ] || die "snapshot verify failed: missing fingerprint"
  [ -f "$published/scope-manifest.b64.tsv" ] || die "snapshot verify failed: missing manifest"
  expected_fp="$(tr -d '\n' <"$published/source-fingerprint.txt")"
  is_hex64 "$expected_fp" || die "snapshot verify failed: invalid stored fingerprint"

  snapshot_temp_trap_on
  dir_a="$(mktemp -d "$cache/.snapshot-verify.XXXXXX")"
  snapshot_temp_register "$dir_a"
  dir_b="$(mktemp -d "$cache/.snapshot-verify.XXXXXX")"
  snapshot_temp_register "$dir_b"
  build_candidate "$target" "$dir_a"
  build_candidate "$target" "$dir_b"
  fp_a="$(<"$dir_a/fingerprint.txt")"
  fp_b="$(<"$dir_b/fingerprint.txt")"

  local ok=0 recomputed="$dir_a/recomputed.manifest"
  build_manifest_from_tree "$published/tree" "$recomputed"
  if [ "$fp_a" = "$fp_b" ] && [ "$fp_a" = "$expected_fp" ] \
    && manifests_match "$dir_a/manifest.sorted" "$dir_b/manifest.sorted" \
    && manifests_match "$published/scope-manifest.b64.tsv" "$dir_a/manifest.sorted" \
    && manifests_match "$published/scope-manifest.b64.tsv" "$recomputed" \
    && [ "$(compute_fingerprint_from_manifest "$recomputed")" = "$expected_fp" ]; then
    ok=1
  fi

  snapshot_temp_trap_off
  [ "$ok" -eq 1 ] || die "snapshot verify failed"
}

snapshot_cleanup() {
  local cache=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --cache)
        cache=$2
        shift 2
        ;;
      *)
        die "unknown snapshot cleanup argument: $1"
        ;;
    esac
  done
  [ -n "$cache" ] || die "cache path required"
  [ -d "$cache" ] || die "cache is not a directory: $cache"
  [ -f "$cache/snapshot-current" ] || die "snapshot cleanup failed: missing snapshot-current"

  local published
  published="$(tr -d '\n' <"$cache/snapshot-current")"
  validate_cleanup_path "$cache" "$published"

  if [ -d "$published" ]; then
    chmod -R u+rwX "$published" 2>/dev/null || true
    rm -rf "$published"
  fi
  rm -f "$cache/snapshot-current"
}

FIVE_PASS_CONTRACT_START='<!-- FIVE-PASS-CONTRACT:START -->'
FIVE_PASS_CONTRACT_END='<!-- FIVE-PASS-CONTRACT:END -->'
SNAPSHOT_CONTRACT_START='<!-- SOURCE-SNAPSHOT-CONTRACT:START -->'
SNAPSHOT_CONTRACT_END='<!-- SOURCE-SNAPSHOT-CONTRACT:END -->'
POLICY_FILE_AGENTS='AGENTS.md'
POLICY_FILE_CLAUDE='CLAUDE.md'
POLICY_FILE_SKILL='llm-sast-scanner-full-scan-loop/SKILL.md'
PASS_ROLE_1='Surface inventory'
PASS_ROLE_2='Class sweep'
PASS_ROLE_3='Differential analysis'
PASS_ROLE_4='Cross-file analysis'
PASS_ROLE_5='Negative-verdict challenge'
VALIDATION_ERRORS=()
DEEP_SENTINEL_LENS=""
DEEP_SENTINEL_FP=""
DEEP_SENTINEL_PASSES=""
DEEP_SENTINEL_CONVERGENCE=""
DEEP_SENTINEL_OK=0
DEEP_PASS_COUNT=0
DEEP_PASS_LOG_OK=0
DEEP_FINAL_PASS=0
DEEP_FINAL_NEW=0
DEEP_HIGHEST_PASS=0
DEEP_BODY_CONVERGENCE=""

validation_error() { VALIDATION_ERRORS+=("$1"); }
validation_fail_if_errors() {
  local msg
  for msg in "${VALIDATION_ERRORS[@]}"; do
    printf 'scan-cache-contract: %s\n' "$msg" >&2
  done
  [ "${#VALIDATION_ERRORS[@]}" -eq 0 ] || exit 1
}
validation_reset() { VALIDATION_ERRORS=(); }
artifact_validation_reset() {
  validation_reset
  DEEP_SENTINEL_LENS=""
  DEEP_SENTINEL_FP=""
  DEEP_SENTINEL_PASSES=""
  DEEP_SENTINEL_CONVERGENCE=""
  DEEP_SENTINEL_OK=0
  DEEP_PASS_COUNT=0
  DEEP_PASS_LOG_OK=0
  DEEP_FINAL_PASS=0
  DEEP_FINAL_NEW=0
  DEEP_HIGHEST_PASS=0
  DEEP_BODY_CONVERGENCE=""
}
final_nonblank_line() { awk 'NF { line = $0 } END { print line }' "$1"; }
extract_marked_block() {
  awk -v start="$2" -v end="$3" '
    $0 == start { capture = 1; next }
    $0 == end { capture = 0; exit }
    capture { print }
  ' "$1"
}
validate_expected_hex64() {
  local label=$1 value=$2
  is_hex64 "$value" || validation_error "$label must be 64 lowercase hexadecimal characters"
}
validate_expected_lens_token() {
  local lens=$1
  [[ $lens =~ ^[a-z][a-z0-9-]*$ ]] || validation_error 'invalid expected lens token'
}
sentinel_matches_deep() {
  printf '%s\n' "$1" | grep -Eq \
    '^<!-- LLM-SAST-COMPLETE lens=[^ ]+ contract=five-pass-v1 source-fingerprint=[0-9a-f]{64} passes=[0-9]+ coverage=100% convergence=.+ -->$'
}
sentinel_matches_shallow() {
  printf '%s\n' "$1" | grep -Eq \
    '^<!-- LLM-SAST-COMPLETE lens=[^ ]+ source-fingerprint=[0-9a-f]{64} -->$'
}
sentinel_matches_report() {
  printf '%s\n' "$1" | grep -Eq \
    '^<!-- LLM-SAST-COMPLETE source-fingerprint=[0-9a-f]{64} -->$'
}
parse_deep_sentinel() {
  local line=$1
  DEEP_SENTINEL_LENS="$(printf '%s' "$line" | sed -n \
    's/^<!-- LLM-SAST-COMPLETE lens=\([^ ]*\) contract=five-pass-v1 source-fingerprint=\([0-9a-f]\{64\}\) passes=\([0-9][0-9]*\) coverage=100% convergence=\(.*\) -->$/\1/p')"
  DEEP_SENTINEL_FP="$(printf '%s' "$line" | sed -n \
    's/^<!-- LLM-SAST-COMPLETE lens=\([^ ]*\) contract=five-pass-v1 source-fingerprint=\([0-9a-f]\{64\}\) passes=\([0-9][0-9]*\) coverage=100% convergence=\(.*\) -->$/\2/p')"
  DEEP_SENTINEL_PASSES="$(printf '%s' "$line" | sed -n \
    's/^<!-- LLM-SAST-COMPLETE lens=\([^ ]*\) contract=five-pass-v1 source-fingerprint=\([0-9a-f]\{64\}\) passes=\([0-9][0-9]*\) coverage=100% convergence=\(.*\) -->$/\3/p')"
  DEEP_SENTINEL_CONVERGENCE="$(printf '%s' "$line" | sed -n \
    's/^<!-- LLM-SAST-COMPLETE lens=\([^ ]*\) contract=five-pass-v1 source-fingerprint=\([0-9a-f]\{64\}\) passes=\([0-9][0-9]*\) coverage=100% convergence=\(.*\) -->$/\4/p')"
}
parse_shallow_sentinel() {
  local line=$1 lens fp
  lens="$(printf '%s' "$line" | sed -n \
    's/^<!-- LLM-SAST-COMPLETE lens=\([^ ]*\) source-fingerprint=\([0-9a-f]\{64\}\) -->$/\1/p')"
  fp="$(printf '%s' "$line" | sed -n \
    's/^<!-- LLM-SAST-COMPLETE lens=\([^ ]*\) source-fingerprint=\([0-9a-f]\{64\}\) -->$/\2/p')"
  SHALLOW_SENTINEL_LENS="$lens"
  SHALLOW_SENTINEL_FP="$fp"
}
parse_report_sentinel() {
  local line=$1
  REPORT_SENTINEL_FP="$(printf '%s' "$line" | sed -n \
    's/^<!-- LLM-SAST-COMPLETE source-fingerprint=\([0-9a-f]\{64\}\) -->$/\1/p')"
}

validate_common_sentinel() {
  local file=$1 mode=$2 expected_lens=${3:-} expected_fp=$4
  local sentinel_count final_line sentinel_count_str
  sentinel_count_str="$(grep -cF '<!-- LLM-SAST-COMPLETE' "$file" 2>/dev/null || true)"
  sentinel_count="${sentinel_count_str:-0}"
  [ "$sentinel_count" -eq 1 ] || validation_error "artifact must contain exactly one completion sentinel (found ${sentinel_count})"
  final_line="$(final_nonblank_line "$file")"
  [ -n "$final_line" ] || validation_error 'artifact missing final nonblank line'
  if [ -n "$final_line" ] && [[ $final_line != '<!-- LLM-SAST-COMPLETE'*' -->' ]]; then
    validation_error 'final nonblank line must be the completion sentinel'
  fi
  [ -n "$final_line" ] && [ "$sentinel_count" -eq 1 ] || return 0
  case "$mode" in
    deep)
      [ -n "$expected_lens" ] || validation_error 'expected lens required for deep artifact validation'
      validate_expected_lens_token "$expected_lens"
      if sentinel_matches_deep "$final_line"; then
        parse_deep_sentinel "$final_line"
        if [ -n "$DEEP_SENTINEL_LENS" ] && [ -n "$DEEP_SENTINEL_FP" ] \
          && [ -n "$DEEP_SENTINEL_PASSES" ] && [ -n "$DEEP_SENTINEL_CONVERGENCE" ]; then
          DEEP_SENTINEL_OK=1
        else
          validation_error 'terminal sentinel does not match required deep artifact shape'
        fi
        if [ "$DEEP_SENTINEL_OK" -eq 1 ] && [ "$DEEP_SENTINEL_LENS" != "$expected_lens" ]; then
          validation_error "terminal sentinel lens=${DEEP_SENTINEL_LENS} does not match expected lens ${expected_lens}"
        fi
        if [ "$DEEP_SENTINEL_OK" -eq 1 ] && [ "$DEEP_SENTINEL_FP" != "$expected_fp" ]; then
          validation_error 'terminal sentinel source fingerprint does not match expected fingerprint'
        fi
      else
        validation_error 'terminal sentinel does not match required deep artifact shape'
      fi
      ;;
    shallow)
      [ -n "$expected_lens" ] || validation_error 'expected lens required for shallow artifact validation'
      validate_expected_lens_token "$expected_lens"
      if sentinel_matches_shallow "$final_line"; then
        parse_shallow_sentinel "$final_line"
        [ "$SHALLOW_SENTINEL_LENS" = "$expected_lens" ] \
          || validation_error "terminal sentinel lens=${SHALLOW_SENTINEL_LENS} does not match expected lens ${expected_lens}"
        [ "$SHALLOW_SENTINEL_FP" = "$expected_fp" ] \
          || validation_error 'terminal sentinel source fingerprint does not match expected fingerprint'
      else
        validation_error 'terminal sentinel does not match required shallow artifact shape'
      fi
      ;;
    report)
      if sentinel_matches_report "$final_line"; then
        parse_report_sentinel "$final_line"
        [ "$REPORT_SENTINEL_FP" = "$expected_fp" ] \
          || validation_error 'terminal sentinel source fingerprint does not match expected fingerprint'
      else
        validation_error 'terminal sentinel does not match required report artifact shape'
      fi
      ;;
    *) validation_error "unknown artifact mode: $mode" ;;
  esac
}

parse_pass_log_line() {
  local line=$1
  PASS_LINE_NUM="" PASS_LINE_ROLE="" PASS_LINE_NEW=""
  printf '%s\n' "$line" | grep -Eq '^- \*\*Pass [0-9]+ — .+ \(\+[0-9]+ new\):\*\*' || return 1
  PASS_LINE_NUM="$(printf '%s' "$line" | sed -n \
    's/^- \*\*Pass \([0-9][0-9]*\) — \([^(+]*\) (\+\([0-9][0-9]*\) new):\*\*.*$/\1/p')"
  PASS_LINE_ROLE="$(printf '%s' "$line" | sed -n \
    's/^- \*\*Pass \([0-9][0-9]*\) — \([^(+]*\) (\+\([0-9][0-9]*\) new):\*\*.*$/\2/p')"
  PASS_LINE_NEW="$(printf '%s' "$line" | sed -n \
    's/^- \*\*Pass \([0-9][0-9]*\) — \([^(+]*\) (\+\([0-9][0-9]*\) new):\*\*.*$/\3/p')"
  [ -n "$PASS_LINE_NUM" ] && [ -n "$PASS_LINE_ROLE" ] && [ -n "$PASS_LINE_NEW" ]
}

validate_deep_pass_log() {
  local file=$1 in_log=0 in_fence=0 pass_log_sections=0 pass_log_duplicate=0
  local -a pass_nums=() pass_roles=() pass_news=()
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$line" = '## Pass log' ]; then
      pass_log_sections=$((pass_log_sections + 1))
      if [ "$pass_log_sections" -gt 1 ]; then
        [ "$pass_log_duplicate" -eq 0 ] && validation_error 'artifact must contain exactly one canonical ## Pass log section'
        pass_log_duplicate=1
      fi
      in_log=1
      continue
    fi
    if [ "$in_log" -eq 1 ] && [[ $line == '## '* ]]; then in_log=0; continue; fi
    [ "$in_log" -eq 1 ] || continue
    if [[ $line == '```'* ]]; then in_fence=$((1 - in_fence)); continue; fi
    [ "$in_fence" -eq 1 ] && continue
    if parse_pass_log_line "$line"; then
      pass_nums+=("$PASS_LINE_NUM")
      pass_roles+=("$PASS_LINE_ROLE")
      pass_news+=("$PASS_LINE_NEW")
    elif [ -n "${line//[[:space:]]/}" ]; then
      validation_error 'pass log accepts only exact "- **Pass N — ROLE (+M new):**" records'
    fi
  done < "$file"
  [ "$pass_log_sections" -eq 1 ] || validation_error 'artifact must contain exactly one canonical ## Pass log section'
  DEEP_PASS_COUNT="${#pass_nums[@]}"
  if [ "$pass_log_sections" -eq 1 ] && [ "$DEEP_PASS_COUNT" -lt 5 ]; then
    validation_error "artifact records fewer than five passes (${DEEP_PASS_COUNT} found)"
  fi
  [ "$pass_log_sections" -eq 1 ] && [ "$DEEP_PASS_COUNT" -ge 5 ] || return 0
  local idx expected_num prev_num=0 expected_role_var
  for idx in "${!pass_nums[@]}"; do
    expected_num=$((idx + 1))
    if [ "${pass_nums[$idx]}" -ne "$expected_num" ]; then
      if [ "${pass_nums[$idx]}" -le "$prev_num" ]; then
        validation_error "duplicate or out-of-order pass ${pass_nums[$idx]} in pass log"
      else
        validation_error "pass numbers must be consecutive beginning at 1 (missing pass ${expected_num})"
      fi
      break
    fi
    prev_num="${pass_nums[$idx]}"
    if [ "$expected_num" -le 5 ]; then
      expected_role_var="PASS_ROLE_${expected_num}"
      [ "${pass_roles[$idx]}" = "${!expected_role_var}" ] \
        || validation_error "pass ${expected_num} role mismatch: expected ${!expected_role_var}, found ${pass_roles[$idx]}"
    fi
  done
  DEEP_FINAL_PASS="${pass_nums[$((DEEP_PASS_COUNT - 1))]}"
  DEEP_FINAL_NEW="${pass_news[$((DEEP_PASS_COUNT - 1))]}"
  DEEP_HIGHEST_PASS="${pass_nums[$((DEEP_PASS_COUNT - 1))]}"
  DEEP_PASS_LOG_OK=1
  if [ "$DEEP_SENTINEL_OK" -eq 1 ]; then
    [ "$DEEP_SENTINEL_PASSES" = "$DEEP_PASS_COUNT" ] \
      || validation_error "terminal sentinel passes=${DEEP_SENTINEL_PASSES} does not match pass log count ${DEEP_PASS_COUNT}"
    [ "$DEEP_SENTINEL_PASSES" = "$DEEP_HIGHEST_PASS" ] \
      || validation_error "terminal sentinel passes=${DEEP_SENTINEL_PASSES} does not match highest pass number ${DEEP_HIGHEST_PASS}"
  fi
}

validate_deep_convergence() {
  local file=$1
  if [ "$DEEP_SENTINEL_OK" -ne 1 ] || [ "$DEEP_PASS_LOG_OK" -ne 1 ]; then
    return 0
  fi
  local in_section=0 in_fence=0 section_count=0
  local -a status_lines=()
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$line" = '## CONVERGENCE STATUS' ]; then
      section_count=$((section_count + 1))
      [ "$section_count" -le 1 ] || validation_error 'artifact must contain exactly one ## CONVERGENCE STATUS section'
      in_section=1
      continue
    fi
    if [ "$in_section" -eq 1 ] && { [[ $line == '## '* ]] || [[ $line == '<!-- LLM-SAST-COMPLETE'* ]]; }; then
      in_section=0
      continue
    fi
    [ "$in_section" -eq 1 ] || continue
    if [[ $line == '```'* ]]; then in_fence=$((1 - in_fence)); continue; fi
    [ "$in_fence" -eq 1 ] && continue
    [ -n "${line//[[:space:]]/}" ] && status_lines+=("$line")
  done < "$file"
  [ "$section_count" -eq 1 ] || validation_error 'artifact must contain exactly one ## CONVERGENCE STATUS section'
  [ "${#status_lines[@]}" -gt 0 ] || validation_error 'missing nonblank convergence status line'
  [ "${#status_lines[@]}" -le 1 ] || validation_error '## CONVERGENCE STATUS must contain exactly one nonblank status line'
  [ "$section_count" -eq 1 ] && [ "${#status_lines[@]}" -eq 1 ] || return 0
  DEEP_BODY_CONVERGENCE="${status_lines[0]}"
  [ "$DEEP_BODY_CONVERGENCE" = "$DEEP_SENTINEL_CONVERGENCE" ] \
    || validation_error 'CONVERGENCE STATUS body does not exactly match sentinel convergence= value'
  if [ "$DEEP_FINAL_NEW" -eq 0 ] && [ "$DEEP_FINAL_PASS" -ge 5 ] && [ "$DEEP_SENTINEL_CONVERGENCE" != 'converged' ]; then
    validation_error "final pass +0 at pass ${DEEP_FINAL_PASS} requires convergence=converged"
  fi
  if [ "$DEEP_FINAL_NEW" -gt 0 ] && [ "$DEEP_FINAL_PASS" -lt 10 ]; then
    validation_error "final pass +${DEEP_FINAL_NEW} new at pass ${DEEP_FINAL_PASS} is incomplete (another pass is mandatory)"
  fi
  if [ "$DEEP_FINAL_NEW" -gt 0 ] && [ "$DEEP_SENTINEL_CONVERGENCE" = 'converged' ]; then
    validation_error "final pass +${DEEP_FINAL_NEW} new cannot claim converged"
  fi
  if [ "$DEEP_FINAL_PASS" -eq 10 ] && [ "$DEEP_FINAL_NEW" -gt 0 ]; then
    local expected_not_converged="NOT CONVERGED (hit pass-10 hard cap; last pass +${DEEP_FINAL_NEW} new)"
    [ "$DEEP_SENTINEL_CONVERGENCE" = "$expected_not_converged" ] \
      || validation_error 'pass 10 with +new findings requires exact NOT CONVERGED hard-cap status'
  fi
  if [ "$DEEP_SENTINEL_CONVERGENCE" = 'converged' ] && { [ "$DEEP_FINAL_PASS" -lt 5 ] || [ "$DEEP_FINAL_NEW" -gt 0 ]; }; then
    validation_error 'converged status requires pass 5+ with +0 new on the final pass'
  fi
  case "$DEEP_SENTINEL_CONVERGENCE" in
    converged) ;;
    NOT\ CONVERGED\ \(hit\ pass-10\ hard\ cap\;\ last\ pass\ +*)
      if [ "$DEEP_FINAL_PASS" -ne 10 ] || [ "$DEEP_FINAL_NEW" -le 0 ]; then
        validation_error 'NOT CONVERGED hard-cap status is valid only at pass 10 with +new findings'
      fi
      case "$DEEP_SENTINEL_CONVERGENCE" in
        *" last pass +${DEEP_FINAL_NEW} new)") ;;
        *) validation_error 'NOT CONVERGED hard-cap status must match final pass new count' ;;
      esac
      ;;
    *) validation_error 'convergence status must be exactly converged or the pass-10 NOT CONVERGED hard-cap form' ;;
  esac
}

artifact_validate_peer_generalization_clearances() {
  local file=$1
  awk '
    function has_file_line(text) {
      return (text ~ /[A-Za-z0-9_.\/-]+:[0-9]+/)
    }
    function has_finding_ref(text) {
      return (text ~ /(reported |CONFIRMED |→|finding )VULN-[0-9]+/ || text ~ /VULN-[0-9]+/)
    }
    function disposition_generalizes(line,    lower) {
      lower = tolower(line)
      if (lower !~ /safe-because/) return 0
      if (lower ~ /on sensitive flows/) return 1
      if (lower ~ /on similar endpoints/) return 1
      if (lower ~ /middleware on sensitive/) return 1
      if (lower ~ /on auth (flows|endpoints|mutations|operations)/) return 1
      if (lower ~ /on (similar|peer) (flows|endpoints|mutations|routes|handlers|operations)/) return 1
      if (lower ~ /peer .* (apply|use|have|share)/) return 1
      return 0
    }
    function check_block(title, body,    line, n, i, disp) {
      if (title ~ /^### \[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/) return
      n = split(body, lines, "\n")
      for (i = 1; i <= n; i++) {
        line = lines[i]
        if (line ~ /\*\*Disposition:\*\*/) {
          disp = line
          sub(/^[^:]*:[[:space:]]*/, "", disp)
          if (disposition_generalizes(disp) && !has_file_line(body) && !has_finding_ref(body)) {
            printf "invalid class-level peer-generalization clearance in %s\n", title
            exit 1
          }
        }
      }
    }
    BEGIN {
      block_title = ""
      block_body = ""
    }
    /^## / {
      if (block_title != "") check_block(block_title, block_body)
      block_title = ""
      block_body = ""
      next
    }
    /^### / {
      if (block_title != "") check_block(block_title, block_body)
      block_title = $0
      block_body = ""
      next
    }
    block_title != "" {
      block_body = block_body $0 "\n"
    }
    END {
      if (block_title != "") check_block(block_title, block_body)
    }
  ' "$file" || {
    validation_error 'class Clearance Record uses peer-generalization SAFE-because without per-hit file:line dispositions or cited outlier finding (see PEER-DIFFERENTIAL CLEARANCE GATE)'
    return 0
  }
}

artifact_validate_deep() {
  local file=$1 expected_lens=$2 expected_fp=$3
  artifact_validation_reset
  [ -f "$file" ] || die "artifact file not found: $file"
  [ -n "$expected_lens" ] || die 'expected lens required'
  [ -n "$expected_fp" ] || die 'expected fingerprint required'
  validate_expected_hex64 'expected fingerprint' "$expected_fp"
  validate_common_sentinel "$file" deep "$expected_lens" "$expected_fp"
  validate_deep_pass_log "$file"
  if [ "$DEEP_SENTINEL_OK" -eq 1 ] && [ "$DEEP_PASS_LOG_OK" -eq 1 ]; then
    validate_deep_convergence "$file"
  fi
  artifact_validate_peer_generalization_clearances "$file"
  validation_fail_if_errors
}
artifact_validate_shallow() {
  local file=$1 expected_lens=$2 expected_fp=$3
  validation_reset
  [ -f "$file" ] || die "artifact file not found: $file"
  [ -n "$expected_lens" ] || die 'expected lens required'
  [ -n "$expected_fp" ] || die 'expected fingerprint required'
  validate_expected_hex64 'expected fingerprint' "$expected_fp"
  validate_common_sentinel "$file" shallow "$expected_lens" "$expected_fp"
  validation_fail_if_errors
}
artifact_validate_report() {
  local file=$1 expected_fp=$2
  validation_reset
  [ -f "$file" ] || die "artifact file not found: $file"
  [ -n "$expected_fp" ] || die 'expected fingerprint required'
  validate_expected_hex64 'expected fingerprint' "$expected_fp"
  validate_common_sentinel "$file" report '' "$expected_fp"
  validation_fail_if_errors
}
artifact_cmd() {
  local mode=${1:-}; shift || true
  local file="" expected_lens="" expected_fp=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --file) file=$2; shift 2 ;;
      --expected-lens) expected_lens=$2; shift 2 ;;
      --expected-fingerprint) expected_fp=$2; shift 2 ;;
      *) die "unknown artifact argument: $1" ;;
    esac
  done
  case "$mode" in
    deep) artifact_validate_deep "$file" "$expected_lens" "$expected_fp" ;;
    shallow) artifact_validate_shallow "$file" "$expected_lens" "$expected_fp" ;;
    report) artifact_validate_report "$file" "$expected_fp" ;;
    *) die "unknown artifact mode: ${mode:-}" ;;
  esac
}

policy_require_fragment() {
  local label=$1 text=$2 fragment=$3
  case "$text" in
    *"$fragment"*) ;;
    *) validation_error "${label}: missing required policy text: ${fragment}" ;;
  esac
}
policy_index_of_file() {
  local file=$1 needle=$2
  awk -v n="$needle" '
    { buf = buf $0 "\n" }
    END { i = index(buf, n); print (i > 0 ? i : 0) }
  ' "$file"
}
policy_absolute_index_in_section() {
  local file=$1 start=$2 end=$3 needle=$4
  awk -v start="$start" -v end="$end" -v n="$needle" '
    BEGIN { in_section = 0; pos = 0; found = 0; use_end = (length(end) > 0) }
    {
      line_start = pos + 1
      pos = pos + length($0) + 1
      if (index($0, start) == 1) { in_section = 1; next }
      if (use_end && in_section && index($0, end) == 1) { in_section = 0 }
      if (in_section) {
        idx = index($0, n)
        if (idx > 0) { print line_start + idx - 1; found = 1; exit }
      }
    }
    END { if (!found) print 0 }
  ' "$file"
}
policy_absolute_index_after_anchor() {
  local file=$1 anchor=$2 needle=$3
  awk -v anchor="$anchor" -v n="$needle" '
    BEGIN { pos = 0; past = 0; found = 0 }
    {
      line_start = pos + 1
      pos = pos + length($0) + 1
      if (index($0, anchor) == 1) { past = 1; next }
      if (past) {
        idx = index($0, n)
        if (idx > 0) { print line_start + idx - 1; found = 1; exit }
      }
    }
    END { if (!found) print 0 }
  ' "$file"
}
policy_count_in_section() {
  local file=$1 start=$2 end=$3 needle=$4
  awk -v start="$start" -v end="$end" -v n="$needle" '
    BEGIN { in_section = 0; count = 0; use_end = (length(end) > 0) }
    {
      if (index($0, start) == 1) { in_section = 1; next }
      if (use_end && in_section && index($0, end) == 1) { in_section = 0 }
      if (in_section && index($0, n) > 0) { count++ }
    }
    END { print count }
  ' "$file"
}
policy_require_memory_barrier() {
  local label=$1 text=$2
  case "$text" in
    *'Never update project memory or run cleanup before'*) return 0 ;;
    *'Never update memory or cleanup before'*) return 0 ;;
    *'Never update project memory or run cleanup before successful snapshot verify'*) return 0 ;;
  esac
  validation_error "${label}: missing memory/cleanup barrier before verify and report validation"
}
policy_validate_intro_and_concurrency() {
  local label=$1 text=$2
  policy_require_fragment "$label" "$text" 'completion marker alone never authorizes skip'
  policy_require_fragment "$label" "$text" 'one active orchestration per target'
  policy_require_fragment "$label" "$text" 'Concurrent whole scans'
  policy_require_fragment "$label" "$text" 'does not provide safe shared cleanup under concurrency'
}
policy_validate_step3_skip_gates() {
  local label=$1 file=$2
  local skip_loop skip_report skip_rerun

  policy_require_fragment "$label" "$(<"$file")" 'ORDINARY_LENS_RERAN'

  if grep -q '^## Ordinary orchestration parity' "$file" 2>/dev/null; then
    skip_loop="$(policy_absolute_index_in_section "$file" "Step 3 skip" "Step 3 generate" \
      'for lens in injection access-auth')"
    skip_report="$(policy_absolute_index_in_section "$file" "Step 3 skip" "Step 3 generate" \
      'scan-cache-contract.sh" artifact report')"
    skip_rerun="$(policy_absolute_index_in_section "$file" "Step 3 skip" "Step 3 generate" \
      'if [ "$ORDINARY_LENS_RERAN" -ne 0 ]')"
  else
    skip_loop="$(policy_absolute_index_in_section "$file" "## Step 3:" "Otherwise launch" \
      'for lens in injection access-auth')"
    skip_report="$(policy_absolute_index_in_section "$file" "## Step 3:" "Otherwise launch" \
      'scan-cache-contract.sh" artifact report')"
    skip_rerun="$(policy_absolute_index_in_section "$file" "## Step 3:" "Otherwise launch" \
      'if [ "$ORDINARY_LENS_RERAN" -ne 0 ]')"
  fi

  if [ "$skip_loop" -eq 0 ]; then
    validation_error "${label}: ordinary Step 3 skip path missing six-lens artifact shallow validation loop"
  fi
  if [ "$skip_rerun" -eq 0 ]; then
    validation_error "${label}: ordinary Step 3 skip path missing ORDINARY_LENS_RERAN no-rerun guard"
  elif [ "$skip_rerun" -ge "$skip_loop" ]; then
    validation_error "${label}: ordinary Step 3 skip path must declare ORDINARY_LENS_RERAN guard before six-lens loop"
  fi
  if [ "$skip_report" -eq 0 ]; then
    validation_error "${label}: ordinary Step 3 skip path missing artifact report validation"
  elif [ "$skip_loop" -ge "$skip_report" ]; then
    validation_error "${label}: ordinary Step 3 skip path must run six-lens shallow loop before artifact report"
  fi
}
policy_validate_completion_paths() {
  local label=$1 file=$2
  local text skip_report skip_verify gen_verify gen_report gen_cleanup gen_memory
  local deep_verify deep_report deep_cleanup single_verify single_report
  text="$(<"$file")"

  policy_require_fragment "$label" "$text" 'scan-cache-contract.sh" artifact report'
  policy_require_memory_barrier "$label" "$text"

  if grep -q '^## Ordinary orchestration parity' "$file" 2>/dev/null; then
    skip_report="$(policy_absolute_index_in_section "$file" "Step 3 skip" "Step 3 generate" \
      'scan-cache-contract.sh" artifact report')"
    skip_verify="$(policy_absolute_index_in_section "$file" "Step 3 skip" "Step 3 generate" \
      'scan-cache-contract.sh" snapshot verify')"
    gen_verify="$(policy_absolute_index_in_section "$file" "Step 3 generate" "## Arguments" \
      'snapshot verify')"
    gen_report="$(policy_absolute_index_in_section "$file" "Step 3 generate" "## Arguments" \
      'artifact report')"
    gen_cleanup="$(policy_absolute_index_in_section "$file" "Step 3 generate" "## Arguments" \
      'snapshot cleanup')"
  else
    skip_report="$(policy_absolute_index_in_section "$file" "## Step 3:" "Otherwise launch" \
      'scan-cache-contract.sh" artifact report')"
    skip_verify="$(policy_absolute_index_in_section "$file" "## Step 3:" "Otherwise launch" \
      'scan-cache-contract.sh" snapshot verify')"
    gen_verify="$(policy_absolute_index_after_anchor "$file" "Otherwise launch" 'snapshot verify')"
    gen_report="$(policy_absolute_index_after_anchor "$file" "Otherwise launch" 'artifact report')"
    gen_cleanup="$(policy_absolute_index_after_anchor "$file" "Otherwise launch" 'snapshot cleanup')"
  fi

  if [ "$skip_report" -eq 0 ] || [ "$skip_verify" -eq 0 ]; then
    validation_error "${label}: ordinary Step 3 skip path missing artifact report or snapshot verify"
  elif [ "$skip_report" -ge "$skip_verify" ]; then
    validation_error "${label}: ordinary Step 3 skip path must run artifact report before snapshot verify"
  fi

  if [ "$gen_verify" -eq 0 ] || [ "$gen_report" -eq 0 ]; then
    validation_error "${label}: ordinary Step 3 generate path missing snapshot verify or artifact report"
  elif [ "$gen_verify" -ge "$gen_report" ]; then
    validation_error "${label}: ordinary Step 3 generate path must run snapshot verify before artifact report"
  fi
  if [ "$gen_cleanup" -gt 0 ] && [ "$gen_report" -ge "$gen_cleanup" ]; then
    validation_error "${label}: ordinary Step 3 generate path must run artifact report before snapshot cleanup"
  fi
  if grep -q '^## Ordinary orchestration parity' "$file" 2>/dev/null; then
    gen_memory="$(policy_absolute_index_in_section "$file" "Step 3 generate" "## Arguments" 'update project memory')"
  else
    gen_memory="$(policy_absolute_index_after_anchor "$file" "Otherwise launch" 'project-memory.md')"
  fi
  if [ "$gen_memory" -gt 0 ] && [ "$gen_report" -gt 0 ] && [ "$gen_report" -ge "$gen_memory" ]; then
    validation_error "${label}: ordinary Step 3 generate path must validate report before updating project memory"
  fi
  if [ "$gen_memory" -gt 0 ] && [ "$gen_verify" -gt 0 ] && [ "$gen_memory" -le "$gen_verify" ]; then
    validation_error "${label}: ordinary Step 3 generate path must run snapshot verify before updating project memory"
  fi

  if grep -q '^### Step D3' "$file" 2>/dev/null; then
    deep_verify="$(policy_absolute_index_after_anchor "$file" "### Step D3" 'snapshot verify')"
    deep_report="$(policy_absolute_index_after_anchor "$file" "### Step D3" 'artifact report')"
    deep_cleanup="$(policy_absolute_index_after_anchor "$file" "### Step D3" 'snapshot cleanup')"
  else
    deep_verify="$(policy_absolute_index_after_anchor "$file" "**Step D3 — Consolidation" 'snapshot verify')"
    deep_report="$(policy_absolute_index_after_anchor "$file" "**Step D3 — Consolidation" 'artifact report')"
    deep_cleanup="$(policy_absolute_index_after_anchor "$file" "**Step D3 — Consolidation" 'snapshot cleanup')"
  fi

  if [ "$deep_verify" -eq 0 ] || [ "$deep_report" -eq 0 ]; then
    validation_error "${label}: deep D3 completion path missing snapshot verify or artifact report"
  elif [ "$deep_verify" -ge "$deep_report" ]; then
    validation_error "${label}: deep D3 completion path must run snapshot verify before artifact report"
  fi
  if [ "$deep_cleanup" -gt 0 ] && [ "$deep_report" -ge "$deep_cleanup" ]; then
    validation_error "${label}: deep D3 completion path must run artifact report before snapshot cleanup"
  fi

  if grep -q 'OUTPUT (single-agent mode)' "$file" 2>/dev/null; then
    single_verify="$(policy_absolute_index_after_anchor "$file" "OUTPUT (single-agent mode)" 'snapshot verify')"
    single_report="$(policy_absolute_index_after_anchor "$file" "OUTPUT (single-agent mode)" 'artifact report')"
  else
    single_verify="$(policy_absolute_index_in_section "$file" "**Single-mode verify barrier" "### Deep Mode" \
      'snapshot verify')"
    single_report="$(policy_absolute_index_in_section "$file" "**Single-mode verify barrier" "### Deep Mode" \
      'artifact report')"
    if [ "$single_verify" -eq 0 ]; then
      single_verify="$(policy_absolute_index_in_section "$file" "### Single-agent (mode=single)" "### Deep Mode" \
        'snapshot verify')"
      single_report="$(policy_absolute_index_in_section "$file" "### Single-agent (mode=single)" "### Deep Mode" \
        'artifact report')"
    fi
  fi

  if [ "$single_verify" -eq 0 ] || [ "$single_report" -eq 0 ]; then
    validation_error "${label}: single-mode completion path missing snapshot verify or artifact report"
  elif [ "$single_verify" -ge "$single_report" ]; then
    validation_error "${label}: single-mode completion path must run snapshot verify before artifact report"
  fi
}
policy_validate_agents_deep_prepare() {
  local label=$1 file=$2
  local deep_prepare_count
  grep -q '^### Deep Mode' "$file" 2>/dev/null || return 0
  deep_prepare_count="$(policy_count_in_section "$file" "### Deep Mode" "" \
    'scan-cache-contract.sh" snapshot prepare')"
  if [ "$deep_prepare_count" -gt 1 ]; then
    validation_error "${label}: deep path must not contain multiple unconditional snapshot prepare calls"
  fi
  if [ "$deep_prepare_count" -eq 1 ]; then
    policy_require_fragment "$label" "$(<"$file")" 'call snapshot prepare again'
  fi
}
policy_validate_flow_order() {
  local label=$1 file=$2
  local ord_prep=0 ord_shallow=0 ord_verify=0
  local deep_prep=0 deep_deep=0 deep_verify=0

  if grep -q '^## Ordinary orchestration parity' "$file" 2>/dev/null; then
    ord_prep="$(policy_absolute_index_in_section "$file" "## Ordinary orchestration parity" "## Arguments" \
      'scan-cache-contract.sh" snapshot prepare')"
    ord_shallow="$(policy_absolute_index_in_section "$file" "## Ordinary orchestration parity" "## Arguments" \
      'scan-cache-contract.sh" artifact shallow')"
    ord_verify="$(policy_absolute_index_in_section "$file" "## Ordinary orchestration parity" "## Arguments" \
      'scan-cache-contract.sh" snapshot verify')"
  else
    ord_prep="$(policy_index_of_file "$file" 'scan-cache-contract.sh" snapshot prepare')"
    ord_shallow="$(policy_index_of_file "$file" 'scan-cache-contract.sh" artifact shallow')"
    ord_verify="$(policy_index_of_file "$file" 'scan-cache-contract.sh" snapshot verify')"
  fi

  if grep -q '^### Step D1' "$file" 2>/dev/null; then
    deep_prep="$(policy_absolute_index_in_section "$file" "### Step D1" "## Convergence Loop Procedure" \
      'scan-cache-contract.sh" snapshot prepare')"
    deep_deep="$(policy_absolute_index_in_section "$file" "### Step D1" "## Convergence Loop Procedure" \
      'scan-cache-contract.sh" artifact deep')"
    deep_verify="$(policy_absolute_index_after_anchor "$file" "### Step D3" \
      'scan-cache-contract.sh" snapshot verify')"
  else
    deep_prep="$(policy_absolute_index_in_section "$file" "### Deep Mode" "" \
      'scan-cache-contract.sh" snapshot prepare')"
    deep_deep="$(policy_absolute_index_in_section "$file" "### Deep Mode" "" \
      'scan-cache-contract.sh" artifact deep')"
    deep_verify="$(policy_absolute_index_after_anchor "$file" "**Step D3 — Consolidation" \
      'scan-cache-contract.sh" snapshot verify')"
  fi

  if [ "$ord_prep" -eq 0 ] || [ "$ord_shallow" -eq 0 ] || [ "$ord_verify" -eq 0 ]; then
    validation_error "${label}: ordinary flow missing prepare, artifact shallow, or snapshot verify operational call"
    return 0
  fi
  if [ "$deep_prep" -eq 0 ] || [ "$deep_deep" -eq 0 ] || [ "$deep_verify" -eq 0 ]; then
    validation_error "${label}: deep flow missing prepare, artifact deep, or snapshot verify operational call"
    return 0
  fi
  if [ "$ord_prep" -ge "$ord_shallow" ] || [ "$ord_shallow" -ge "$ord_verify" ]; then
    validation_error "${label}: ordinary flow must order snapshot prepare → artifact shallow → snapshot verify"
  fi
  if [ "$deep_prep" -ge "$deep_deep" ] || [ "$deep_deep" -ge "$deep_verify" ]; then
    validation_error "${label}: deep flow must order snapshot prepare → artifact deep → snapshot verify"
  fi
}
policy_first_artifact_index_file() {
  local file=$1
  local shallow deep
  shallow="$(policy_index_of_file "$file" 'scan-cache-contract.sh" artifact shallow')"
  deep="$(policy_index_of_file "$file" 'scan-cache-contract.sh" artifact deep')"
  if [ "$shallow" -eq 0 ]; then
    printf '%s' "$deep"
  elif [ "$deep" -eq 0 ]; then
    printf '%s' "$shallow"
  elif [ "$shallow" -lt "$deep" ]; then
    printf '%s' "$shallow"
  else
    printf '%s' "$deep"
  fi
}
policy_validate_operational_order() {
  local label=$1 file=$2
  local prep verify artifact cleanup
  prep="$(policy_index_of_file "$file" 'scan-cache-contract.sh" snapshot prepare')"
  verify="$(policy_index_of_file "$file" 'scan-cache-contract.sh" snapshot verify')"
  artifact="$(policy_first_artifact_index_file "$file")"
  cleanup="$(policy_index_of_file "$file" 'snapshot cleanup')"

  if [ "$prep" -eq 0 ]; then
    validation_error "${label}: missing snapshot prepare operational call"
    return 0
  fi
  if [ "$verify" -eq 0 ]; then
    validation_error "${label}: missing snapshot verify operational call"
    return 0
  fi
  if [ "$artifact" -eq 0 ]; then
    validation_error "${label}: missing artifact shallow/deep operational call"
    return 0
  fi

  if [ "$prep" -ge "$artifact" ]; then
    validation_error "${label}: snapshot prepare must precede strict artifact validation"
  fi
  if [ "$artifact" -ge "$verify" ]; then
    validation_error "${label}: strict artifact validation must precede snapshot verify"
  fi
  if [ "$cleanup" -gt 0 ] && [ "$verify" -ge "$cleanup" ]; then
    validation_error "${label}: snapshot verify must precede snapshot cleanup"
  fi
}
policy_validate_five_pass_block() {
  local label=$1 block=$2
  policy_require_fragment "$label" "$block" 'contract=five-pass-v1'
  policy_require_fragment "$label" "$block" 'Passes 1–5 are mandatory'
  policy_require_fragment "$label" "$block" "$PASS_ROLE_1"
  policy_require_fragment "$label" "$block" "$PASS_ROLE_2"
  policy_require_fragment "$label" "$block" "$PASS_ROLE_3"
  policy_require_fragment "$label" "$block" "$PASS_ROLE_4"
  policy_require_fragment "$label" "$block" "$PASS_ROLE_5"
}
policy_validate_snapshot_block() {
  local label=$1 block=$2
  policy_require_fragment "$label" "$block" 'source-fingerprint-v2'
  policy_require_fragment "$label" "$block" 'before threat modeling or any skip decision'
  policy_require_fragment "$label" "$block" 'original target-relative paths'
  policy_require_fragment "$label" "$block" 'strict shell artifact validation'
  policy_require_fragment "$label" "$block" 'Immediately before a completion sentinel'
  policy_require_fragment "$label" "$block" 'Cleanup occurs only after a successful final report'
}
policy_validate_operational() {
  local label=$1 path=$2 text
  text="$(<"$path")"
  policy_require_fragment "$label" "$text" 'scan-cache-contract.sh" snapshot prepare'
  policy_require_fragment "$label" "$text" 'snapshot-current'
  policy_require_fragment "$label" "$text" 'SNAPSHOT_ROOT'
  policy_require_fragment "$label" "$text" 'scan-cache-contract.sh" artifact shallow'
  policy_require_fragment "$label" "$text" 'scan-cache-contract.sh" artifact deep'
  policy_require_fragment "$label" "$text" 'scan-cache-contract.sh" artifact report'
  policy_require_fragment "$label" "$text" '--expected-lens'
  policy_require_fragment "$label" "$text" '--expected-fingerprint'
  policy_require_fragment "$label" "$text" 'scan-cache-contract.sh" snapshot verify'
  policy_require_fragment "$label" "$text" 'original target-relative paths'
  case "$text" in
    *validate_scan_regression.py*) validation_error "${label}: forbidden runtime reference to validate_scan_regression.py" ;;
    *git\ ls-files*) validation_error "${label}: forbidden runtime reference to git ls-files" ;;
    *'git ls-files --cached --others --exclude-standard'*) validation_error "${label}: forbidden duplicated live enumeration via git ls-files" ;;
    *'find . -type f'*) validation_error "${label}: forbidden duplicated live enumeration via find . -type f" ;;
  esac
  policy_validate_operational_order "$label" "$path"
  policy_validate_flow_order "$label" "$path"
  policy_validate_intro_and_concurrency "$label" "$text"
  policy_validate_step3_skip_gates "$label" "$path"
  policy_validate_completion_paths "$label" "$path"
}
policy_validate_file() {
  local root=$1
  local rel=$2
  local path="$root/$rel"
  local text five_block snap_block
  if [ ! -f "$path" ]; then
    if [ "$rel" = "$POLICY_FILE_CLAUDE" ]; then
      return 0
    fi
    validation_error "${rel}: file not found"
    return 0
  fi
  text="$(<"$path")"
  five_block="$(extract_marked_block "$path" "$FIVE_PASS_CONTRACT_START" "$FIVE_PASS_CONTRACT_END")"
  if [ -z "$five_block" ]; then
    validation_error "${rel}: missing ${FIVE_PASS_CONTRACT_START} … ${FIVE_PASS_CONTRACT_END} block"
  else
    policy_validate_five_pass_block "$rel" "$five_block"
  fi
  snap_block="$(extract_marked_block "$path" "$SNAPSHOT_CONTRACT_START" "$SNAPSHOT_CONTRACT_END")"
  if [ -z "$snap_block" ]; then
    validation_error "${rel}: missing ${SNAPSHOT_CONTRACT_START} … ${SNAPSHOT_CONTRACT_END} block"
  else
    policy_validate_snapshot_block "$rel" "$snap_block"
  fi
  policy_validate_operational "$rel" "$path"
  if [ "$rel" = "$POLICY_FILE_AGENTS" ] || [ "$rel" = "$POLICY_FILE_CLAUDE" ]; then
    policy_validate_agents_deep_prepare "$rel" "$path"
  fi
  POLICY_FIVE_BLOCK="$five_block"
  POLICY_SNAP_BLOCK="$snap_block"
}
policy_cmd() {
  local root=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --root) root=$2; shift 2 ;;
      *) die "unknown policy argument: $1" ;;
    esac
  done
  [ -n "$root" ] || die 'policy root required'
  validate_dir root "$root"
  validation_reset
  local agents_block="" skill_block="" agents_snap="" skill_snap=""
  policy_validate_file "$root" "$POLICY_FILE_AGENTS"
  agents_block="$POLICY_FIVE_BLOCK"
  agents_snap="$POLICY_SNAP_BLOCK"
  policy_validate_file "$root" "$POLICY_FILE_CLAUDE"
  policy_validate_file "$root" "$POLICY_FILE_SKILL"
  skill_block="$POLICY_FIVE_BLOCK"
  skill_snap="$POLICY_SNAP_BLOCK"
  if [ -n "$agents_block" ] && [ -n "$skill_block" ] && [ "$agents_block" != "$skill_block" ]; then
    validation_error "${POLICY_FILE_AGENTS} and ${POLICY_FILE_SKILL} five-pass contract blocks are not byte-identical"
  fi
  if [ -n "$agents_snap" ] && [ -n "$skill_snap" ] && [ "$agents_snap" != "$skill_snap" ]; then
    validation_error "${POLICY_FILE_AGENTS} and ${POLICY_FILE_SKILL} source-snapshot contract blocks are not byte-identical"
  fi
  validation_fail_if_errors
  printf 'policy validation passed\n'
}
cache_preamble_is_stale() {
  local cache=$1 fp=$2
  local preamble="$cache/_lens-agent-preamble.md"
  [ -f "$preamble" ] || return 1
  grep -qF 'a pass finds NO new bug in YOUR lens → converged' "$preamble" 2>/dev/null && return 0
  grep -qF "source-fingerprint=${fp}" "$preamble" 2>/dev/null || return 0
  return 1
}
cache_invalidate_stale_preamble() {
  local cache=$1 fp=$2
  if cache_preamble_is_stale "$cache" "$fp"; then
    rm -f "$cache/_lens-agent-preamble.md"
  fi
}

main() {
  local cmd=${1:-}
  shift || true
  case "$cmd" in
    snapshot)
      local sub=${1:-}
      shift || true
      case "$sub" in
        prepare) snapshot_prepare "$@" ;;
        verify) snapshot_verify "$@" ;;
        cleanup) snapshot_cleanup "$@" ;;
        *) die "unknown snapshot subcommand: ${sub:-}" ;;
      esac
      ;;
    artifact)
      local mode=${1:-}
      shift || true
      artifact_cmd "$mode" "$@"
      printf 'artifact validation passed\n'
      ;;
    policy)
      policy_cmd "$@"
      ;;
    "")
      die "usage: scan-cache-contract.sh <command> ..."
      ;;
    *)
      die "unknown command: $cmd"
      ;;
  esac
}

main "$@"
