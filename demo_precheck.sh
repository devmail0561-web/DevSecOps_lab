#!/usr/bin/env bash
# ============================================================
# Préparation complète de la démo vidéo
# Lance, configure et vérifie tout l'environnement
# Usage : bash demo_precheck.sh
# ============================================================

set +e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

COMPOSE_DIR="/home/virus-one/cours_simac_l3/Semestre_6/Sec_data/projet/labs_v2/lab1-jenkins"
export DOCKER_HOST="unix:///home/virus-one/.docker/desktop/docker.sock"

ok()   { echo -e "  ${GREEN}✓${NC} $1"; ((PASS++)); }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; ((WARN++)); }
fail() { echo -e "  ${RED}✗${NC} $1"; ((FAIL++)); }
info() { echo -e "  ${CYAN}→${NC} $1"; }

header() {
    echo -e "\n${BOLD}[$1] $2${NC}"
}

wait_http() {
    local url="$1" max="$2" label="$3"
    for i in $(seq 1 $max); do
        CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "$url" 2>/dev/null || echo "000")
        if [ "$CODE" = "200" ] || [ "$CODE" = "302" ]; then
            return 0
        fi
        echo -ne "  ${CYAN}→${NC} Attente $label ($i/${max})...\r"
        sleep 5
    done
    echo ""
    return 1
}

echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  PREPARATION DEMO VIDEO — Sécurité des Données  ${NC}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"

# ══════════════════════════════════════════════════════════════
# ÉTAPE 1 — Docker
# ══════════════════════════════════════════════════════════════
header "1/8" "Docker"

if ! docker info &>/dev/null; then
    fail "Docker daemon inaccessible"
    echo -e "\n  ${RED}${BOLD}Docker doit tourner. Lance Docker Desktop puis relance ce script.${NC}\n"
    exit 1
fi
ok "Docker daemon accessible"

# ══════════════════════════════════════════════════════════════
# ÉTAPE 2 — Conteneurs (lancer si absents)
# ══════════════════════════════════════════════════════════════
header "2/8" "Conteneurs Docker"

# Vérifier si un autre conteneur occupe le port 8080
CONFLICT=$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep "0.0.0.0:8080" | grep -v jenkins || true)
if [ -n "$CONFLICT" ]; then
    CTR_NAME=$(echo "$CONFLICT" | awk '{print $1}')
    info "Port 8080 occupé par '$CTR_NAME' — arrêt..."
    docker stop "$CTR_NAME" &>/dev/null
    docker rm "$CTR_NAME" &>/dev/null
    ok "Conteneur '$CTR_NAME' arrêté (libère le port 8080)"
fi

# Lancer docker compose
NEED_UP=false
for ctr in juiceshop jenkins mailhog; do
    STATUS=$(docker inspect -f '{{.State.Status}}' $ctr 2>/dev/null || echo "absent")
    if [ "$STATUS" != "running" ]; then
        NEED_UP=true
        break
    fi
done

if [ "$NEED_UP" = true ]; then
    info "Lancement de docker compose..."
    (cd "$COMPOSE_DIR" && docker compose up -d 2>&1 | tail -5)
    echo ""
fi

for ctr in juiceshop jenkins mailhog; do
    STATUS=$(docker inspect -f '{{.State.Status}}' $ctr 2>/dev/null || echo "absent")
    if [ "$STATUS" = "running" ]; then
        ok "Conteneur $ctr running"
    else
        fail "Conteneur $ctr ($STATUS)"
    fi
done

# Vérifier les ports de mailhog (bug connu : ports pas bindés au restart)
MH_PORT=$(docker inspect mailhog --format '{{range $k, $v := .NetworkSettings.Ports}}{{range $v}}{{.HostPort}}{{end}} {{end}}' 2>/dev/null)
if ! echo "$MH_PORT" | grep -q "8025"; then
    info "MailHog sans ports exposés — recréation..."
    (cd "$COMPOSE_DIR" && docker compose stop mailhog && docker compose rm -f mailhog && docker compose up -d mailhog) &>/dev/null
    sleep 2
    ok "MailHog recréé avec ports"
fi

# ══════════════════════════════════════════════════════════════
# ÉTAPE 3 — Attente des services HTTP
# ══════════════════════════════════════════════════════════════
header "3/8" "Services HTTP"

if wait_http "http://localhost:3000" 12 "Juice Shop"; then
    ok "Juice Shop http://localhost:3000"
else
    fail "Juice Shop ne répond pas après 60s"
fi

if wait_http "http://localhost:8080/login" 12 "Jenkins"; then
    ok "Jenkins http://localhost:8080"
else
    fail "Jenkins ne répond pas après 60s"
fi

if wait_http "http://localhost:8025" 6 "MailHog"; then
    ok "MailHog http://localhost:8025"
else
    fail "MailHog ne répond pas après 30s"
fi

# ══════════════════════════════════════════════════════════════
# ÉTAPE 4 — Jenkins : correction branche si nécessaire
# ══════════════════════════════════════════════════════════════
header "4/8" "Jenkins — job et branche"

JOB_EXISTS=$(curl -s -u admin:admin123 "http://localhost:8080/job/juice-shop-security/api/json" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('name',''))" 2>/dev/null)

if [ "$JOB_EXISTS" = "juice-shop-security" ]; then
    ok "Job juice-shop-security existe"

    BRANCH=$(curl -s -u admin:admin123 "http://localhost:8080/job/juice-shop-security/config.xml" 2>/dev/null | grep -o '\*/[a-z]*' || echo "?")
    if [ "$BRANCH" = "*/main" ]; then
        ok "Branche : */main"
    else
        info "Branche '$BRANCH' → correction vers */main..."
        curl -s -u admin:admin123 "http://localhost:8080/job/juice-shop-security/config.xml" > /tmp/jk_cfg.xml
        sed -i 's|\*/master|\*/main|g' /tmp/jk_cfg.xml

        COOKIE_JAR=/tmp/jk_cookies
        curl -s -u admin:admin123 -c "$COOKIE_JAR" http://localhost:8080/crumbIssuer/api/json > /tmp/jk_crumb.json 2>/dev/null
        CRUMB_F=$(python3 -c "import json; print(json.load(open('/tmp/jk_crumb.json'))['crumbRequestField'])" 2>/dev/null)
        CRUMB_V=$(python3 -c "import json; print(json.load(open('/tmp/jk_crumb.json'))['crumb'])" 2>/dev/null)

        HTTP=$(curl -s -u admin:admin123 -b "$COOKIE_JAR" \
            -H "${CRUMB_F}:${CRUMB_V}" -X POST \
            "http://localhost:8080/job/juice-shop-security/config.xml" \
            -H "Content-Type: application/xml" \
            --data-binary @/tmp/jk_cfg.xml -w "%{http_code}" -o /dev/null 2>/dev/null)

        if [ "$HTTP" = "200" ]; then
            ok "Branche corrigée → */main"
        else
            fail "Correction branche échouée (HTTP $HTTP)"
        fi
        rm -f /tmp/jk_cfg.xml /tmp/jk_cookies /tmp/jk_crumb.json
    fi
else
    fail "Job juice-shop-security absent — le créer manuellement dans Jenkins"
fi

# ══════════════════════════════════════════════════════════════
# ÉTAPE 5 — ngrok
# ══════════════════════════════════════════════════════════════
header "5/8" "ngrok"

NGROK_URL=$(curl -s http://127.0.0.1:4040/api/tunnels 2>/dev/null | python3 -c "
import sys, json
try:
    for t in json.load(sys.stdin).get('tunnels', []):
        if t['public_url'].startswith('https'):
            print(t['public_url']); break
except: pass
" 2>/dev/null)

if [ -z "$NGROK_URL" ]; then
    if command -v ngrok &>/dev/null; then
        info "Lancement de ngrok http 8080..."
        ngrok http 8080 --log=stdout > /tmp/ngrok_demo.log 2>&1 &
        sleep 4

        NGROK_URL=$(curl -s http://127.0.0.1:4040/api/tunnels 2>/dev/null | python3 -c "
import sys, json
try:
    for t in json.load(sys.stdin).get('tunnels', []):
        if t['public_url'].startswith('https'):
            print(t['public_url']); break
except: pass
" 2>/dev/null)

        if [ -n "$NGROK_URL" ]; then
            ok "ngrok lancé : $NGROK_URL"
        else
            fail "ngrok lancé mais pas de tunnel HTTPS"
        fi
    else
        fail "ngrok non installé (snap install ngrok)"
    fi
else
    ok "ngrok déjà actif : $NGROK_URL"
fi

# ══════════════════════════════════════════════════════════════
# ÉTAPE 6 — Webhook GitHub (mise à jour URL si changée)
# ══════════════════════════════════════════════════════════════
header "6/8" "Webhook GitHub"

if command -v gh &>/dev/null && [ -n "$NGROK_URL" ]; then
    HOOK_DATA=$(gh api repos/devmail0561-web/DevSecOps_lab/hooks 2>/dev/null | python3 -c "
import sys, json
hooks = json.load(sys.stdin)
for h in hooks:
    url = h.get('config', {}).get('url', '')
    hid = h.get('id', 0)
    active = h.get('active', False)
    print(f'{hid}|{url}|{active}')
" 2>/dev/null)

    EXPECTED_URL="${NGROK_URL}/github-webhook/"

    if [ -n "$HOOK_DATA" ]; then
        HOOK_ID=$(echo "$HOOK_DATA" | cut -d'|' -f1)
        HOOK_URL=$(echo "$HOOK_DATA" | cut -d'|' -f2)
        HOOK_ACTIVE=$(echo "$HOOK_DATA" | cut -d'|' -f3)

        if [ "$HOOK_URL" = "$EXPECTED_URL" ] && [ "$HOOK_ACTIVE" = "True" ]; then
            ok "Webhook OK : $HOOK_URL"
        else
            info "Mise à jour webhook → $EXPECTED_URL"
            gh api repos/devmail0561-web/DevSecOps_lab/hooks/$HOOK_ID \
                -X PATCH \
                -f "config[url]=$EXPECTED_URL" \
                -f "config[content_type]=json" \
                -F "active=true" \
                --silent 2>/dev/null

            if [ $? -eq 0 ]; then
                ok "Webhook mis à jour : $EXPECTED_URL"
            else
                warn "Mise à jour webhook échouée — le faire manuellement sur GitHub"
            fi
        fi

        info "Envoi d'un ping de test..."
        PING_CODE=$(gh api repos/devmail0561-web/DevSecOps_lab/hooks/$HOOK_ID/pings -X POST 2>&1)
        sleep 2
        LAST_DELIVERY=$(gh api "repos/devmail0561-web/DevSecOps_lab/hooks/$HOOK_ID/deliveries" --jq '.[0].status_code' 2>/dev/null)
        if [ "$LAST_DELIVERY" = "200" ]; then
            ok "Ping webhook → HTTP 200"
        else
            warn "Ping webhook → HTTP $LAST_DELIVERY"
        fi
    else
        info "Aucun webhook existant — création..."
        gh api repos/devmail0561-web/DevSecOps_lab/hooks \
            -X POST \
            -f "name=web" \
            -f "config[url]=$EXPECTED_URL" \
            -f "config[content_type]=json" \
            -F "active=true" \
            -f "events[]=push" \
            --silent 2>/dev/null

        if [ $? -eq 0 ]; then
            ok "Webhook créé : $EXPECTED_URL"
        else
            fail "Création webhook échouée"
        fi
    fi
elif [ -z "$NGROK_URL" ]; then
    warn "Pas de ngrok → skip webhook"
else
    warn "gh CLI absent → vérifier le webhook manuellement sur GitHub"
fi

# ══════════════════════════════════════════════════════════════
# ÉTAPE 7 — Test SQLi (vérifie que Juice Shop est exploitable)
# ══════════════════════════════════════════════════════════════
header "7/8" "Test SQLi"

SQLI_RESULT=$(curl -s -X POST -H "Content-Type: application/json" \
  -d "{\"email\":\"' OR '1'='1'--\",\"password\":\"x\"}" \
  http://localhost:3000/rest/user/login 2>/dev/null)

if echo "$SQLI_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'token' in d.get('authentication',{})" 2>/dev/null; then
    ok "SQLi fonctionne — JWT admin obtenu"
else
    fail "SQLi ne fonctionne pas"
fi

# ══════════════════════════════════════════════════════════════
# ÉTAPE 8 — Fichiers du projet
# ══════════════════════════════════════════════════════════════
header "8/8" "Fichiers projet"

BASE="$(cd "$(dirname "$0")" && pwd)"
[ -d "$BASE/projet_examen" ] && BASE="$BASE/projet_examen"

for f in reports/rapport_final_examen.html reports/hdwp/findings.json \
         remediation/sqli_fix.js remediation/jwt_fix.js remediation/bfla_fix.js \
         juiceshop-hdwp-context.yaml Jenkinsfile DEMO_VIDEO.md; do
    if [ -f "$BASE/$f" ]; then
        ok "$f"
    else
        fail "$f manquant"
    fi
done

# ══════════════════════════════════════════════════════════════
# BILAN
# ══════════════════════════════════════════════════════════════
echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}✓ $PASS${NC}  ${YELLOW}⚠ $WARN${NC}  ${RED}✗ $FAIL${NC}"

if [ -n "$NGROK_URL" ]; then
    echo -e "\n  ${BOLD}ngrok :${NC} $NGROK_URL"
fi

echo -e "  ${BOLD}Juice Shop :${NC} http://localhost:3000"
echo -e "  ${BOLD}Jenkins    :${NC} http://localhost:8080  (admin / admin123)"
echo -e "  ${BOLD}MailHog    :${NC} http://localhost:8025"

if [ "$FAIL" -eq 0 ]; then
    echo -e "\n  ${GREEN}${BOLD}PRET POUR L'ENREGISTREMENT${NC}\n"
else
    echo -e "\n  ${RED}${BOLD}$FAIL PROBLEME(S) — corriger et relancer ce script${NC}\n"
fi
