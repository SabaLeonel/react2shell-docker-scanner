#!/usr/bin/env bash

# ============================================================================
# React2Shell (CVE-2025-55182) - Docker container scanner (Coolify / Next.js)
# ============================================================================
# Scans Docker containers to detect vulnerable versions of:
#   - react-server-dom-webpack
#   - react-server-dom-parcel
#   - react-server-dom-turbopack
#
# Vulnerable versions: 19.0.0, 19.1.0, 19.1.1, 19.2.0
#
# Usage:
#   sudo bash react2shell-docker-scan.sh
# ============================================================================

set -uo pipefail  # no -e to avoid silent exits

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

VULN_VERSIONS=("19.0.0" "19.1.0" "19.1.1" "19.2.0")
RSC_PACKAGES=("react-server-dom-webpack" "react-server-dom-parcel" "react-server-dom-turbopack")

# Likely app roots inside containers
DEFAULT_APP_ROOTS=("/app" "/usr/src/app" "/srv" "/workspace" "/node" "/var/www")

echo -e "${BLUE}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🔍 React2Shell Docker Scanner v2 (CVE-2025-55182)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${NC}"
echo "📅 Date  : $(date)"
echo "📍 Host  : $(hostname)"
echo ""

if ! command -v docker >/dev/null 2>&1; then
  echo -e "${RED}❌ docker not found on host.${NC}"
  exit 1
fi

containers=$(docker ps --format '{{.ID}} {{.Names}} {{.Image}}')

echo -e "${BLUE}📋 Detected containers:${NC}"
if [[ -z "$containers" ]]; then
  echo "  (no running containers)"
  exit 0
fi

echo "$containers" | sed 's/^/  • /'
echo ""

vuln_containers=0
checked_containers=0

echo -e "${BLUE}━━━ 🔎 Scanning application containers ━━━${NC}"
echo ""

while read -r line; do
  [[ -z "$line" ]] && continue

  cid=$(echo "$line" | awk '{print $1}')
  cname=$(echo "$line" | awk '{print $2}')
  cimage=$(echo "$line" | awk '{print $3}')

  # Skip Coolify / DB / cache / proxy infra containers
  if [[ "$cname" =~ ^coolify($|-)|coolify-db|coolify-redis|coolify-sentinel|coolify-proxy ]]; then
    echo -e "${YELLOW}↷ Skipping infra container: $cname ($cimage)${NC}"
    continue
  fi
  if [[ "$cimage" == postgres:* ]] || [[ "$cimage" == redis:* ]] || [[ "$cimage" == traefik:* ]]; then
    echo -e "${YELLOW}↷ Skipping DB/cache/proxy container: $cname ($cimage)${NC}"
    continue
  fi

  ((checked_containers++))

  echo -e "${BLUE}📦 Container:${NC} $cname"
  echo "    ID    : $cid"
  echo "    Image : $cimage"

  # 1) Get WorkingDir
  working_dir=$(docker inspect -f '{{.Config.WorkingDir}}' "$cid" 2>/dev/null || echo "")
  app_roots=()

  if [[ -n "$working_dir" ]]; then
    app_roots+=("$working_dir")
  fi

  # 2) Add default paths
  for d in "${DEFAULT_APP_ROOTS[@]}"; do
    app_roots+=("$d")
  done

  # 3) Keep only directories that actually exist in the container
  roots_cmd="for d in ${app_roots[*]}; do [ -d \"\$d\" ] && printf '%s ' \"\$d\"; done"
  roots=$(docker exec "$cid" sh -lc "$roots_cmd" 2>/dev/null || echo "")

  if [[ -z "$roots" ]]; then
    echo -e "    ${YELLOW}⚠ No app directory detected (WorkingDir + defaults do not exist). Skipping.${NC}"
    echo ""
    continue
  fi

  echo "    Roots scanned : $roots"

  container_vuln=0

  for pkg in "${RSC_PACKAGES[@]}"; do
    files_with_pkg=$(docker exec "$cid" sh -lc \
      "grep -RIl '$pkg' $roots 2>/dev/null | head -50" || echo "")

    if [[ -z "$files_with_pkg" ]]; then
      continue
    fi

    while read -r f; do
      [[ -z "$f" ]] && continue

      for ver in "${VULN_VERSIONS[@]}"; do
        if docker exec "$cid" sh -lc "grep -q '$ver' '$f' 2>/dev/null"; then
          if [[ $container_vuln -eq 0 ]]; then
            echo -e "    ${RED}🚨 Potentially vulnerable:${NC}"
            container_vuln=1
            ((vuln_containers++))
          fi
          echo "      • $pkg @ $ver found in: $f"
        fi
      done
    done <<< "$files_with_pkg"
  done

  if [[ $container_vuln -eq 0 ]]; then
    echo -e "    ${GREEN}✅ No vulnerable RSC package detected (heuristic text scan).${NC}"
  fi

  echo ""
done <<< "$containers"

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}                       📋 SUMMARY${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "🧩 App containers scanned      : $checked_containers"
echo "⚠ Containers flagged vulnerable: $vuln_containers"
echo ""

if [[ $vuln_containers -gt 0 ]]; then
  echo -e "${RED}❌ Some containers appear to ship vulnerable RSC versions (React2Shell).${NC}"
  echo ""
  echo "Recommended actions:"
  echo "  1) Update your apps (Next.js / React) to use patched RSC libraries."
  echo "  2) Rebuild and redeploy the apps via Coolify."
  echo ""
else
  echo -e "${GREEN}✅ No container flagged as vulnerable by this heuristic scan.${NC}"
  echo ""
fi
