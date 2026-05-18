#!/usr/bin/env bash
# Build and decompile artifact (Maven) for parity check.
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 --repo <path> --state-dir <path>
Outputs:
  - <state-dir>/decompile_status.json (status, reason)
  - <state-dir>/decompiled/ (if successful)
EOF
}

REPO=""
STATE=""
JAVA_OVERRIDE="${DECOMPILE_JAVA_HOME:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2;;
    --state-dir) STATE="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) usage; exit 1;;
  esac
done

[[ -z "$REPO" || -z "$STATE" ]] && { usage; exit 1; }

STATUS_JSON="$STATE/decompile_status.json"
OUTDIR="$STATE/decompiled"
mkdir -p "$OUTDIR"

status() {
  local s="$1"; shift
  jq -n --arg status "$s" --arg reason "$*" '{status:$status, reason:$reason}' > "$STATUS_JSON"
}

set_java_home() {
  local selector="$1"
  # explicit override path
  if [[ "$selector" == "override" && -n "$JAVA_OVERRIDE" && -d "$JAVA_OVERRIDE" ]]; then
    export JAVA_HOME="$JAVA_OVERRIDE"
    export PATH="$JAVA_HOME/bin:$PATH"
    echo "[decompile] JAVA_HOME from DECOMPILE_JAVA_HOME: $JAVA_HOME"
    return 0
  fi
  [[ -z "$selector" ]] && return 1
  if command -v /usr/libexec/java_home >/dev/null 2>&1; then
    local jh
    jh=$(/usr/libexec/java_home -v "$selector" 2>/dev/null || true)
    if [[ -n "$jh" && -d "$jh" ]]; then
      export JAVA_HOME="$jh"
      export PATH="$JAVA_HOME/bin:$PATH"
      echo "[decompile] JAVA_HOME set to $JAVA_HOME (java $selector)"
      return 0
    fi
  fi
  return 1
}

run_build() {
  if [[ -f "pom.xml" ]]; then
    echo "[decompile] build (mvn -q -DskipTests clean package)"
    mvn -q -DskipTests clean package
  elif [[ -x "./gradlew" ]]; then
    echo "[decompile] build (./gradlew assemble -x test)"
    ./gradlew assemble -x test >/dev/null
  else
    return 2
  fi
}

cd "$REPO"

build_ok=0
last_err="no build tool"
set +e
for choice in override 17 11 1.8 ""; do
  if set_java_home "$choice"; then
    if run_build; then
      build_ok=1
      last_err=""
      break
    else
      last_err="build failed with java ${JAVA_HOME:-system}"
    fi
  fi
done
set -e

if [[ $build_ok -ne 1 ]]; then
  status "failed" "${last_err:-build failed (maven/gradle)}"
  exit 1
fi

artifact=$(ls target/*.war target/*.jar build/libs/*.jar 2>/dev/null | head -n1 || true)
if [[ -z "$artifact" ]]; then
  status "failed" "no artifact found under target/ or build/libs/"
  exit 1
fi

# locate CFR
CFR_JAR="$(cd "$(dirname "$0")" && pwd)/../cfr-0.152.jar"
if [[ ! -f "$CFR_JAR" ]]; then
  if command -v cfr >/dev/null 2>&1; then
    CFR_JAR=$(command -v cfr)
  else
    status "failed" "CFR not found (expected tools/cfr-0.152.jar or cfr in PATH)"
    exit 1
  fi
fi

echo "[decompile] running CFR on $artifact"
if ! java -jar "$CFR_JAR" "$artifact" --outputdir "$OUTDIR" --silent true >/dev/null 2>&1; then
  status "failed" "cfr decompile failed"
  exit 1
fi

status "success" "decompiled to $OUTDIR"
echo "[decompile] success"
