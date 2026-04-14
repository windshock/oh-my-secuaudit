#!/usr/bin/env bash
# Enumerate auth mechanisms across all controllers in target modules.
# Produces a per-module summary of endpoint count and auth coverage.
# Usage:
#   ./auth_enum.sh                    # all modules
#   ./auth_enum.sh <module_path>      # single module
set -euo pipefail

# --- ADAPT: Set REPO_ROOT to target repository root ---
REPO_ROOT="${REPO_ROOT:-$(pwd)}"

# --- ADAPT: List target modules ---
MODULES=(
  # "src/main/java/com/example/api"
  # "modules/auth-service"
)

TARGETS=("$@")
if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=("${MODULES[@]}")
fi

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  echo "ERROR: No modules configured. Edit MODULES array or pass paths as arguments." >&2
  exit 1
fi

echo "# C1 Auth/Authz Enumeration"
echo ""
echo "| Module | Controllers | Endpoints | @PreAuthorize/@Secured | Auth Interceptor | Service-layer Auth | Verdict |"
echo "|---|---:|---:|---:|---|---|---|"

for module in "${TARGETS[@]}"; do
  module_path="$REPO_ROOT/$module"
  [[ ! -d "$module_path" ]] && continue

  # Count controllers
  controllers=$(grep -rl '@Controller\|@RestController' "$module_path" --include='*.java' 2>/dev/null | grep -v '/target/' | grep -v '/test/' | wc -l | tr -d ' ')

  # Count endpoints
  endpoints=$(grep -rh '@RequestMapping\|@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping\|@PatchMapping' "$module_path" --include='*.java' 2>/dev/null | grep -v '/target/' | grep -v '/test/' | wc -l | tr -d ' ')

  # Check auth annotations
  auth_annot=$(grep -rl '@PreAuthorize\|@Secured\|@RolesAllowed' "$module_path" --include='*.java' 2>/dev/null | grep -v '/target/' | grep -v '/test/' | wc -l | tr -d ' ')

  # Check for auth interceptors in WebConfig/SecurityConfig
  auth_interceptor="none"
  if grep -rq 'addInterceptors\|SecurityFilterChain\|WebSecurityConfigurerAdapter\|@EnableWebSecurity' "$module_path" --include='*.java' 2>/dev/null; then
    # Check if it's actually an auth interceptor vs just logging
    if grep -rq 'AuthInterceptor\|LoginInterceptor\|TokenInterceptor\|JwtInterceptor\|SessionInterceptor' "$module_path" --include='*.java' 2>/dev/null; then
      auth_interceptor="**present**"
    else
      auth_interceptor="logging-only"
    fi
  fi

  # Check service-layer auth
  svc_auth="none"
  if grep -rq 'verifySignature\|validateToken\|checkAuth\|hmacVerify\|chkSign\|verifyHmac' "$module_path" --include='*.java' 2>/dev/null; then
    svc_auth="**present**"
  fi

  # Verdict
  verdict="review"
  if [[ "$auth_annot" -eq 0 && "$auth_interceptor" == "none" && "$svc_auth" == "none" ]]; then
    verdict="**NO AUTH**"
  elif [[ "$auth_annot" -eq 0 && "$auth_interceptor" == "logging-only" && "$svc_auth" == "none" ]]; then
    verdict="**NO AUTH** (logging-only interceptor)"
  fi

  echo "| $module | $controllers | $endpoints | $auth_annot | $auth_interceptor | $svc_auth | $verdict |"
done
