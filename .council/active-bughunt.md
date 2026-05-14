# Active Council Bughunt Candidate Report

This report is not a pass/fail proof. It is a fresh queue of suspicious shapes
that sit outside, or at the edge of, the current closed sweep gates. A green
all-phases council run means registered gates passed; it does not mean these
candidate lines are bugs or that no bugs exist.

Classification rule: any accepted row must be ledgered, fixed with behavior
coverage, sibling-swept, and promoted into a durable gate before closure.

## Async void boundaries

## Silent catch or lossy exception boundaries

## Callback/event invocation boundaries

## Remote/user text in diagnostics or HTTP errors

## Red-team abuse lens
docs/dev/bug-council-active-backlog.md:34:| `Red-team abuse lens` | 108 | Open | Required recurring attacker-view review across secrets, identity, redirects, paths, process launch, and downgrade risks. | Turn accepted hypotheses into behavior tests plus remediation anchors; add preservation tests for normal functionality. |
docs/dev/bug-council-negative-space.md:19:| _replace_with_your_boundary_ | _network input_ | `src/path/to/sink.ext` | `ValidateInputName` |
docs/dev/bug-council-roslyn-analyzers.md:23:| CSL0004 | TaintToFilePath | High | Network-derived file/directory path without sanctioned containment validation. This catches hostile paths before filesystem sinks trust them. |
docs/dev/bug-council-phases.md:8:| 2 | Semantic analyzer beachhead | _Pending / In progress / Done_ | _agent_ | One language-appropriate semantic analyzer (Roslyn / Clippy / ESLint) implementing a taint-to-allocation or taint-to-path lens, with tests. |
docs/dev/bug-council-phases.md:16:| 10 | Additional semantic lens batch | _Pending / In progress / Done_ | _agent_ | Add several distinct semantic lenses in one batch, such as tainted protocol offsets, paths, timeouts, endpoints, enum/status conversions, slice bounds, diagnostic/log-line text, outbound messages, cache keys, crypto trust material, dynamic execution, parser runtimes, resource capacities, and buffer operations, with unit tests and calibration. |
scripts/check-remediation-baseline.sh:24:  local path="$1"
scripts/check-remediation-baseline.sh:27:  if [[ -f "$path" ]]; then
scripts/check-remediation-baseline.sh:30:    fail "$label: missing $path"
scripts/check-remediation-baseline.sh:36:  local path="$2"
scripts/check-remediation-baseline.sh:39:  if rg -n -U --pcre2 --hidden --glob '!.git/**' "$pattern" "$path" >/dev/null; then
scripts/check-remediation-baseline.sh:48:  local path="$2"
scripts/check-remediation-baseline.sh:54:  if rg -n -U --pcre2 --hidden --glob '!.git/**' "$pattern" "$path" >"$hit_file" 2>/dev/null; then
scripts/check-remediation-baseline.sh:109:# require_pattern "ValidateInputName" "src/path/to/sink" "input validator wired"
scripts/check-remediation-baseline.sh:110:# require_pattern "MaxRequestSize" "src/path/to/limit" "request size bound declared"
scripts/check-remediation-baseline.sh:113:secret_pattern='-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9_]{36,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16}|(?i)(api[_-]?key|access[_-]?token|client[_-]?secret)["'\'']?\s*[:=]\s*["'\''][A-Za-z0-9_./+=-]{24,}["'\'']'
scripts/check-remediation-baseline.sh:114:require_absent_pattern "$secret_pattern" "." "tracked text files do not contain high-confidence secret patterns"
scripts/check-council-sweep-counts.sh:82:#   "secret-pattern sweep count matches scanner"
scripts/scan-bug-council-candidates.sh:24:  rg -n --with-filename --pcre2 --hidden --glob '!.git/**' "$pattern" "$@" || true
scripts/scan-bug-council-candidates.sh:33:  'PRIVATE KEY|gh[pousr]_[A-Za-z0-9_]{36,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16}|(?i)(api[_-]?key|access[_-]?token|client[_-]?secret)' \
scripts/scan-bug-council-candidates.sh:57:#   'tokio::spawn|select!|timeout\(|sleep\(|interval\(|mpsc|broadcast|oneshot' \
scripts/check-local-identity-leaks.sh:17:tmp_tokens="$(mktemp)"
scripts/check-local-identity-leaks.sh:20:trap 'rm -f "$tmp_tokens" "$tmp_commits" "$tmp_files"' EXIT
scripts/check-local-identity-leaks.sh:22:add_token() {
scripts/check-local-identity-leaks.sh:23:  local token="$1"
scripts/check-local-identity-leaks.sh:24:  token="${token//$'\n'/}"
scripts/check-local-identity-leaks.sh:25:  token="${token//$'\r'/}"
scripts/check-local-identity-leaks.sh:26:  [[ ${#token} -ge 3 ]] || return 0
scripts/check-local-identity-leaks.sh:27:  case "$token" in
scripts/check-local-identity-leaks.sh:32:  printf '%s\n' "$token" >>"$tmp_tokens"
scripts/check-local-identity-leaks.sh:35:add_token "${LOCAL_IDENTITY_DENYLIST:-}"
scripts/check-local-identity-leaks.sh:36:add_token "${SLSKDN_LOCAL_IDENTITY_DENYLIST:-}"
scripts/check-local-identity-leaks.sh:37:add_token "${SLSKDN_FORBIDDEN_LOCAL_HOSTNAME:-}"
scripts/check-local-identity-leaks.sh:38:add_token "$(hostname -s 2>/dev/null || true)"
scripts/check-local-identity-leaks.sh:39:add_token "${USER:-}"
scripts/check-local-identity-leaks.sh:40:add_token "$(id -un 2>/dev/null || true)"
scripts/check-local-identity-leaks.sh:41:add_token "$(basename "${HOME:-}" 2>/dev/null || true)"
scripts/check-local-identity-leaks.sh:43:read_csv_tokens() {
scripts/check-local-identity-leaks.sh:46:  IFS=',' read -ra tokens <<<"$value"
scripts/check-local-identity-leaks.sh:47:  for token in "${tokens[@]}"; do
scripts/check-local-identity-leaks.sh:48:    add_token "$token"
scripts/check-local-identity-leaks.sh:52:read_csv_tokens "${LOCAL_IDENTITY_DENYLIST:-}"
scripts/check-local-identity-leaks.sh:53:read_csv_tokens "${SLSKDN_LOCAL_IDENTITY_DENYLIST:-}"
scripts/check-local-identity-leaks.sh:58:  while IFS= read -r token; do
scripts/check-local-identity-leaks.sh:59:    [[ "$token" =~ ^[[:space:]]*# ]] && continue
scripts/check-local-identity-leaks.sh:60:    add_token "$token"
scripts/check-local-identity-leaks.sh:67:sort -u "$tmp_tokens" -o "$tmp_tokens"
scripts/check-local-identity-leaks.sh:68:if [[ ! -s "$tmp_tokens" ]]; then
scripts/check-local-identity-leaks.sh:69:  echo "No local identity tokens configured for scanning."
scripts/check-local-identity-leaks.sh:77:  local path="$2"
scripts/check-local-identity-leaks.sh:78:  local display_path="${3:-$path}"
scripts/check-local-identity-leaks.sh:81:  [[ -f "$path" ]] || return 0
scripts/check-local-identity-leaks.sh:83:    rg --json --fixed-strings --ignore-case --file "$tmp_tokens" "$path" |
scripts/check-local-identity-leaks.sh:84:      jq -r --arg label "$label" --arg display_path "$display_path" 'select(.type == "match") | "\($label): \($display_path):\(.data.line_number)"' |
scripts/check-local-identity-leaks.sh:96:  trap 'rm -f "$tmp_tokens" "$tmp_commits" "$tmp_files" "$tmp_unreleased"' EXIT
scripts/check-local-identity-leaks.sh:117:  -path './.git' -prune -o \
scripts/check-local-identity-leaks.sh:118:  -path './node_modules' -prune -o \
scripts/check-local-identity-leaks.sh:119:  -path './vendor' -prune -o \
scripts/check-local-identity-leaks.sh:120:  -path './target' -prune -o \
scripts/check-local-identity-leaks.sh:121:  -path './dist' -prune -o \
scripts/check-local-identity-leaks.sh:122:  -path './build' -prune -o \
scripts/check-local-identity-leaks.sh:123:  -path './zeek/pkg' -prune -o \
scripts/check-local-identity-leaks.sh:125:    -path './.github/release-notes/*' -o \
scripts/check-local-identity-leaks.sh:126:    -path './docs/dev/release-copy.md' -o \
scripts/check-local-identity-leaks.sh:127:    -path './docs/release*.md' -o \
scripts/check-local-identity-leaks.sh:128:    -path './docs/RELEASE*.md' -o \
scripts/check-local-identity-leaks.sh:129:    -path './packaging/winget/*' \
scripts/check-local-identity-leaks.sh:132:while IFS= read -r path; do
scripts/check-local-identity-leaks.sh:133:  [[ -n "$path" ]] || continue
scripts/check-local-identity-leaks.sh:134:  check_file "$path" "$path"
scripts/corpus_compare.py:4:from pathlib import Path
scripts/corpus_compare.py:9:def read_fp(path: Path) -> tuple[float, bytes]:
scripts/corpus_compare.py:12:    for line in path.read_text(encoding="utf-8").splitlines():
scripts/corpus_compare.py:18:        raise ValueError(f"missing duration or fingerprint in {path}")
scripts/corpus_compare.py:22:def load_meta(fp_path: Path) -> tuple[str, str]:
scripts/corpus_compare.py:23:    meta_path = fp_path.with_suffix("").with_suffix(".meta.json")
scripts/corpus_compare.py:24:    label = fp_path.stem.replace(".fp", "")
scripts/corpus_compare.py:25:    if meta_path.exists():
scripts/corpus_compare.py:27:            data = json.loads(meta_path.read_text(encoding="utf-8"))
scripts/corpus_compare.py:31:    return label, str(meta_path)
scripts/corpus_compare.py:41:    query_path = Path(args.query)
scripts/corpus_compare.py:43:    query_fp = read_fp(query_path)
scripts/corpus_compare.py:46:    for fp_path in sorted(corpus_dir.glob("*.fp.txt")):
scripts/corpus_compare.py:48:            candidate_fp = read_fp(fp_path)
scripts/corpus_compare.py:52:        label, meta_path = load_meta(fp_path)
scripts/corpus_compare.py:53:        rows.append((score, label, str(fp_path), meta_path))
scripts/corpus_compare.py:56:    for score, label, fp_path, meta_path in rows[: args.top]:
scripts/corpus_compare.py:57:      print(f"{score:.6f}\t{label}\t{fp_path}\t{meta_path}")
scripts/acoustid_lookup.py:10:def lookup_http(api_key: str, duration: int, fingerprint: str) -> dict:
scripts/acoustid_lookup.py:13:            ("client", api_key),
scripts/acoustid_lookup.py:21:        "https://api.acoustid.org/v2/lookup",
scripts/acoustid_lookup.py:37:def lookup_pyacoustid(api_key: str, duration: int, fingerprint: str) -> dict:
scripts/acoustid_lookup.py:41:        api_key,
scripts/acoustid_lookup.py:58:    parser.add_argument("--api-key", required=True)
scripts/acoustid_lookup.py:66:        data = lookup_pyacoustid(args.api_key, args.duration, args.fingerprint)
scripts/acoustid_lookup.py:68:        data = lookup_http(args.api_key, args.duration, args.fingerprint)
scripts/acoustid_lookup.py:72:            data = lookup_pyacoustid(args.api_key, args.duration, args.fingerprint)
scripts/acoustid_lookup.py:74:            data = lookup_http(args.api_key, args.duration, args.fingerprint)
docs/dev/bug-council-scan-registry.md:39:| Untrusted-string-to-path | Find file-system operations on caller-supplied strings without containment. |
docs/dev/bug-council-scan-registry.md:40:| Security-sensitive material | Find high-confidence private keys and token patterns. |
docs/dev/bug-council-scan-registry.md:41:| Red-team abuse lens | Re-check accepted fixes from an attacker viewpoint: spoofed identity, secret disclosure, confused deputy, replay, SSRF/path/process escape, and operational downgrade. |
scripts/check-council-negative-space.sh:65:#   "src/path/to/sink.ext" \
scripts/check-bug-council-all-phases.sh:26:  printf 'Council all-phases runner is missing or not executable: %s\n' "${runner#$repo_root/}" >&2
scripts/run-council-active-bughunt.sh:25:    rg -n -U --with-filename --pcre2 --hidden --glob '!.git/**' --glob '!.council/**' "$pattern" "$@" || true
scripts/run-council-active-bughunt.sh:41:# Replace paths and patterns for your repo. Add narrow sections whenever a
scripts/run-council-active-bughunt.sh:61:  '(log|logger|Diagnostic|Console\.WriteLine|StatusCode\(|BadRequest\()[^;\n]*(username|query|filename|directory|token|message)' \
scripts/run-council-active-bughunt.sh:66:  '(token|secret|password|authorization|cookie|api[-_]?key|session|redirect|proxy|forwarded|path|filename|exec|spawn|shell|http://|https://)' \
docs/dev/bug-council-severity-schema.md:12:| Low | Defensive-depth gap: code path is currently unreachable from untrusted input, but the absence of the guard is itself a hazard if a refactor exposes it. |
docs/dev/bug-council-severity-schema.md:15:Pick the **worst plausible** severity given current code paths. If the same code is reachable from two boundaries with different severities, take the higher.

## Public mutable ownership surfaces
