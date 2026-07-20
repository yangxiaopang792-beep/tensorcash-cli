
    #!/usr/bin/env bash
    set -euo pipefail

    BIN=""
    OUT_DIR=""
    SUITE=""
    TEST_NAME=""
    FILTER=""
    EXTRA_ARGS=()
    ENV_PAIRS=()
    KEEP_DIRS=0
    VERBOSE=0
    LIST_ONLY=0

    usage() {
      cat <<EOF
    Run Boost tests in isolation, one by one.

    Options:
      --binary PATH           Path to test_bitcoin (auto-detect by default)
      --suite NAME            Run all tests in suite NAME (e.g. argsman_tests)
      --test NAME             Run a single test (e.g. miner_tests/CreateNewBlock_validity)
      --filter REGEX          Grep filter applied to discovered tests
      --out DIR               Output directory (default: ./test-logs/<timestamp>)
      --env 'K=V ...'         Space-separated env assignments passed to each run
      --args '...'	         Extra args passed to test binary (after --)
      --keep-dirs             Keep per-test datadirs (default copies debug.log only)
      --verbose               Print more info while running
      --list                  List test names and exit
      -h, --help              Show this help
    EOF
    }

    timestamp() { date +%Y%m%d-%H%M%S; }
    log() { echo "[run] $*"; }
    die() { echo "[error] $*" >&2; exit 1; }

    find_binary() {
      local candidates=(
        "./build/bin/test_bitcoin"
        "services/core-node/bcore/build/bin/test_bitcoin"
        "./src/test/test_bitcoin"
      )
      for c in "${candidates[@]}"; do
        if [[ -x "$c" ]]; then BIN="$c"; return; fi
      done
      die "test_bitcoin binary not found. Build it or pass --binary PATH"
    }

    while [[ $# -gt 0 ]]; do
      case "$1" in
        --binary) shift; BIN="${1:-}" ;;
        --suite) shift; SUITE="${1:-}" ;;
        --test) shift; TEST_NAME="${1:-}" ;;
        --filter) shift; FILTER="${1:-}" ;;
        --out) shift; OUT_DIR="${1:-}" ;;
        --env) shift; IFS=' ' read -r -a ENV_PAIRS <<< "${1:-}" ;;
        --args) shift; IFS=' ' read -r -a EXTRA_ARGS <<< "${1:-}" ;;
        --keep-dirs) KEEP_DIRS=1 ;;
        --verbose) VERBOSE=1 ;;
        --list) LIST_ONLY=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown option: $1" ;;
      esac
      shift || true
    done

    [[ -n "$BIN" ]] || find_binary
    [[ -n "$OUT_DIR" ]] || OUT_DIR="./test-logs/$(timestamp)"
    mkdir -p "$OUT_DIR"

    discover_tests() {
      "$BIN" --list_content 2>/dev/null |
        awk '{gsub("\r","",$0); if ($1 ~ /^[[:alnum:]_]+\/[[:alnum:]_]+$/) print $1; else if ($1 ~ /^[[:alnum:]_]+$/) last=$1; else if ($1 ~ /^[[:space:]]+[[:alnum:]_]+$/ && last!="") {gsub(/^[[:space:]]+/,"",$1); print last"/"$1}}'
    }

    TESTS=()
    if [[ -n "$TEST_NAME" ]]; then
      TESTS=("$TEST_NAME")
    elif [[ -n "$SUITE" ]]; then
      while IFS= read -r t; do TESTS+=("$t"); done < <(discover_tests | grep -E "^${SUITE}/")
    else
      while IFS= read -r t; do TESTS+=("$t"); done < <(discover_tests)
    fi

    if [[ -n "$FILTER" ]]; then
      mapfile -t TESTS < <(printf '%s
' "${TESTS[@]}" | grep -E "$FILTER" || true)
    fi

    if [[ $LIST_ONLY -eq 1 ]]; then
      printf '%s
' "${TESTS[@]}"
      exit 0
    fi

    [[ ${#TESTS[@]} -gt 0 ]] || die "No tests selected. Use --suite/--test/--filter or --list"

    log "Binary: $BIN"
    log "Output: $OUT_DIR"
    log "Tests: ${#TESTS[@]}"

    PASS=0; FAIL=0
    FAILED_LIST=( )

    for t in "${TESTS[@]}"; do
      SAFE_NAME=${t//\//_}
      TDIR="$OUT_DIR/$SAFE_NAME"
      DBDIR="$TDIR/datadir"
      mkdir -p "$DBDIR"

      [[ $VERBOSE -eq 1 ]] && log "Running $t"

      (
        set -o pipefail
        for kv in "${ENV_PAIRS[@]:-}"; do export "$kv"; done
        "$BIN" --run_test="$t" --           DEBUG_LOG_OUT           -printtoconsole=1 -logtimemicros -logthreadnames           -debug=validation           -testdatadir="$DBDIR"           "${EXTRA_ARGS[@]:-}"           >"$TDIR/stdout.log" 2>&1
      )
      RC=$?

      DBG=$(find "$DBDIR" -type f -name debug.log -print -quit 2>/dev/null || true)
      if [[ -n "$DBG" ]]; then cp "$DBG" "$TDIR/debug.log" || true; fi
      if [[ $KEEP_DIRS -eq 0 ]]; then rm -rf "$DBDIR" || true; fi

      if [[ $RC -eq 0 ]]; then
        PASS=$((PASS+1))
        echo "[ OK ] $t"
      else
        FAIL=$((FAIL+1))
        FAILED_LIST+=("$t")
        echo "[FAIL] $t (rc=$RC) — see $TDIR/stdout.log ${DBG:+and $TDIR/debug.log}"
      fi
    done

    echo ""
    echo "Summary: PASS=$PASS FAIL=$FAIL TOTAL=$((PASS+FAIL))"
    if [[ $FAIL -gt 0 ]]; then
      echo "Failed tests:"
      printf '  %s
' "${FAILED_LIST[@]}"
      exit 1
    fi
