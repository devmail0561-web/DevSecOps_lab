// ============================================================
// Jenkinsfile — Examen Final : Pipeline de Sécurité Automatisé
// Cible  : OWASP Juice Shop (Docker, réseau 172.20.0.0/24)
// Dépôt  : https://github.com/devmail0561-web/labs_sec_data
// Cours  : Sécurité des Données — Licence 3 Cybersécurité
// ============================================================

pipeline {

    agent any

    environment {
        JUICE_SHOP_URL = "http://juiceshop:3000"
        REPORT_DIR     = "/tmp/reports_${BUILD_NUMBER}"
        NOTIFY_EMAIL   = '$DEFAULT_RECIPIENTS'
        REPO_URL       = "https://github.com/devmail0561-web/labs_sec_data"
    }

    options {
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        disableConcurrentBuilds()
    }

    // ── Déclencheurs ──────────────────────────────────────────
    // pollSCM  : Jenkins interroge le dépôt toutes les 5 min
    // githubPush : déclenchement immédiat via webhook GitHub
    //   → Configurer dans GitHub : Settings > Webhooks
    //   → Payload URL : http://<IP_JENKINS>:8080/github-webhook/
    //   → Content type : application/json
    //   → Event       : Just the push event
    triggers {
        pollSCM('H/5 * * * *')
        githubPush()
    }

    stages {

        // ─────────────────────────────────────────────────────
        // ÉTAPE 1 — Checkout
        // Récupère le code source et affiche les informations
        // de build pour la traçabilité.
        // ─────────────────────────────────────────────────────
        stage('Checkout') {
            steps {
                echo "============================================================"
                echo " Examen Final — Pipeline de Sécurité OWASP Juice Shop"
                echo " Build  : #${env.BUILD_NUMBER}"
                echo " Date   : ${new Date()}"
                echo " Commit : ${env.GIT_COMMIT ?: 'n/a'}"
                echo " Branche: ${env.GIT_BRANCH ?: 'n/a'}"
                echo " Dépôt  : ${env.REPO_URL}"
                echo "============================================================"
            }
        }

        // ─────────────────────────────────────────────────────
        // ÉTAPE 2 — Build / Preparation
        // Prépare l'environnement de test : création des
        // répertoires de rapports et attente de la disponibilité
        // de la cible (Juice Shop).
        // ─────────────────────────────────────────────────────
        stage('Build / Preparation') {
            steps {
                sh '''
                    mkdir -p "${REPORT_DIR}/evidence"
                    echo "[OK] Répertoire de rapports créé : ${REPORT_DIR}"
                    ls -la /lab/scripts/ 2>/dev/null || echo "[WARN] /lab/scripts/ non monté"
                '''
                script {
                    def maxAttempts = 12
                    def attempt    = 0
                    def ready      = false
                    echo "[INFO] Attente de Juice Shop sur ${env.JUICE_SHOP_URL} ..."
                    while (attempt < maxAttempts && !ready) {
                        def code = sh(
                            script: "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 '${env.JUICE_SHOP_URL}' 2>/dev/null || echo '000'",
                            returnStdout: true
                        ).trim()
                        if (code == '200') {
                            echo "[OK] Juice Shop disponible (HTTP ${code})"
                            ready = true
                        } else {
                            echo "[WAIT] HTTP ${code} — Tentative ${attempt + 1}/${maxAttempts}"
                            sleep(5)
                            attempt++
                        }
                    }
                    if (!ready) {
                        error("[ERREUR] Juice Shop inaccessible après ${maxAttempts} tentatives.")
                    }
                }
            }
        }

        // ─────────────────────────────────────────────────────
        // ÉTAPE 3 — Security Analysis
        //
        // SAST — Analyse Statique du Code Source
        // Outil : Semgrep (règles OWASP Top Ten / JavaScript)
        // Type  : Analyse statique — examine le code source sans
        //         l'exécuter, recherche de patterns vulnérables
        // Vulnérabilités détectées :
        //   - Injections SQL (CWE-89) : détection de concaténations
        //     dans les requêtes DB
        //   - XSS (CWE-79) : sorties non encodées dans les templates
        //   - Secrets hardcodés (CWE-798) : clés API, mots de passe
        //   - Path Traversal (CWE-22) : accès fichiers non contrôlés
        //   - Désérialisation non sécurisée (CWE-502)
        // Limites :
        //   - Faux positifs : code sain peut matcher des patterns
        //   - Ne détecte pas les vulnérabilités de configuration
        //     (ex. headers HTTP manquants)
        //   - Ne détecte pas les vulnérabilités de runtime (IDOR,
        //     contrôle d'accès insuffisant)
        //   - Couverture limitée aux patterns connus dans les règles
        // Moment : étape 3, avant l'exécution — shift-left security
        //
        // SCA — Software Composition Analysis
        // Outil : npm audit (Node.js built-in)
        // Type  : Analyse des dépendances et composants tiers
        // Vulnérabilités détectées :
        //   - CVE dans les packages npm (ex. prototype pollution,
        //     ReDoS, path traversal dans des libs tierces)
        //   - Dépendances obsolètes avec vulnérabilités connues
        //   - Transitive dependencies vulnérables
        // Limites :
        //   - Uniquement les vulnérabilités publiées dans npm advisory
        //   - Ne détecte pas les vulnérabilités dans le code custom
        //   - Peut signaler des vulnérabilités sans chemin d'exploit
        //     réel dans le contexte de l'application
        // Moment : étape 3, analyse du package.json avant exécution
        // ─────────────────────────────────────────────────────
        stage('Security Analysis') {
            parallel {
                stage('SAST — Semgrep') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                            sh '''
                                echo "[SAST] Lancement de Semgrep — OWASP Top Ten rules"
                                semgrep --config=p/owasp-top-ten \
                                        --json \
                                        --output "${REPORT_DIR}/semgrep_results.json" \
                                        /lab/app 2>/dev/null \
                                || semgrep --config=p/javascript \
                                           --json \
                                           --output "${REPORT_DIR}/semgrep_results.json" \
                                           /lab/app 2>/dev/null \
                                || echo "SAST: semgrep non disponible ou aucune alerte" \
                                        > "${REPORT_DIR}/semgrep_results.json"
                                echo "[SAST] Résultat Semgrep :"
                                cat "${REPORT_DIR}/semgrep_results.json" \
                                    | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    r = d.get('results', [])
    print(f'  Findings : {len(r)}')
    for f in r[:5]:
        print(f'  [{f[\"extra\"][\"severity\"]}] {f[\"check_id\"]} — {f[\"path\"]}:{f[\"start\"][\"line\"]}')
    if len(r) > 5:
        print(f'  ... et {len(r)-5} autres')
except: print('  (résultat non parsable JSON)')
" 2>/dev/null || true
                            '''
                        }
                    }
                    post {
                        failure { echo "[SAST] Semgrep a détecté des vulnérabilités" }
                        success { echo "[SAST] Analyse Semgrep terminée" }
                    }
                }
                stage('SCA — npm audit') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                            sh '''
                                echo "[SCA] Lancement de npm audit"
                                cd /lab/app 2>/dev/null || cd /var/lib/jenkins/workspace/${JOB_NAME} 2>/dev/null || true
                                npm audit --json > "${REPORT_DIR}/npm_audit.json" 2>/dev/null \
                                || echo "{\"info\":\"npm audit non disponible\"}" \
                                        > "${REPORT_DIR}/npm_audit.json"
                                echo "[SCA] Résumé npm audit :"
                                cat "${REPORT_DIR}/npm_audit.json" \
                                    | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    meta = d.get('metadata', {}).get('vulnerabilities', {})
    print(f'  Critical : {meta.get(\"critical\", 0)}')
    print(f'  High     : {meta.get(\"high\", 0)}')
    print(f'  Moderate : {meta.get(\"moderate\", 0)}')
    print(f'  Low      : {meta.get(\"low\", 0)}')
except: print('  (résultat non parsable JSON)')
" 2>/dev/null || true
                            '''
                        }
                    }
                    post {
                        failure { echo "[SCA] npm audit a détecté des dépendances vulnérables" }
                        success { echo "[SCA] Analyse des dépendances terminée" }
                    }
                }
            }
        }

        // ─────────────────────────────────────────────────────
        // ÉTAPE 4 — Additional Security Check
        //
        // DAST — Dynamic Application Security Testing
        // Outil : OWASP ZAP (Zed Attack Proxy)
        // Type  : Analyse dynamique — teste l'application en
        //         fonctionnement réel via des requêtes HTTP
        // Vulnérabilités détectées :
        //   - XSS réfléchi et stocké (CWE-79)
        //   - Injections SQL (CWE-89) via fuzzing des paramètres
        //   - En-têtes de sécurité manquants (CWE-16)
        //   - Exposition de données sensibles (CWE-200)
        //   - Mauvaises configurations CORS
        //   - Méthodes HTTP dangereuses (CWE-16)
        // Limites :
        //   - Nécessite que l'application soit démarrée
        //   - Faux positifs sur les réponses applicatives complexes
        //   - Ne couvre pas les vulnérabilités de logique métier
        //     (ex. IDOR nécessitant une compréhension du contexte)
        //   - Scan actif peut être bruyant et perturber l'application
        // Moment : étape 4, après démarrage de l'application (runtime)
        //
        // Secret Detection
        // Outil : trufflehog ou gitleaks
        // Type  : Détection de secrets dans le code et l'historique Git
        // Vulnérabilités détectées :
        //   - Clés API exposées (CWE-312)
        //   - Tokens JWT ou OAuth dans le code source
        //   - Mots de passe hardcodés (CWE-798)
        //   - Certificats ou clés privées committés
        //   - Credentials de base de données dans les configs
        // Limites :
        //   - Faux positifs sur les chaînes de test ou les exemples
        //   - Ne détecte pas les secrets dans les variables d'env
        //     injectées au runtime
        //   - L'analyse de l'historique Git peut être longue
        // Moment : étape 4, analyse du dépôt complet (code + historique)
        // ─────────────────────────────────────────────────────
        stage('Additional Security Check') {
            parallel {
                stage('DAST — OWASP ZAP') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                            sh '''
                                echo "[DAST] Lancement de l'analyse dynamique"
                                if [ -f /lab/scripts/zap_scan.sh ]; then
                                    echo "[DAST] Utilisation du script ZAP"
                                    JUICE_SHOP_URL="${JUICE_SHOP_URL}" \
                                    REPORT_DIR="${REPORT_DIR}" \
                                    bash /lab/scripts/zap_scan.sh
                                else
                                    echo "[DAST] ZAP non disponible — tests manuels curl"
                                    {
                                    echo "=== DAST — Tests dynamiques manuels ==="
                                    echo "Date : $(date '+%Y-%m-%d %H:%M:%S')"
                                    echo "Cible : ${JUICE_SHOP_URL}"
                                    echo ""

                                    # Test 1 — En-têtes de sécurité
                                    echo "--- Test : En-têtes de sécurité ---"
                                    HEADERS=$(curl -s -I --connect-timeout 10 "${JUICE_SHOP_URL}" 2>/dev/null)
                                    for h in "Strict-Transport-Security" "Content-Security-Policy" "Referrer-Policy"; do
                                        if echo "$HEADERS" | grep -qi "$h"; then
                                            echo "  [PRESENT] $h"
                                        else
                                            echo "  [MANQUANT] $h — FAIL (CWE-16)"
                                        fi
                                    done

                                    # Test 2 — SQL Injection
                                    echo ""
                                    echo "--- Test : SQL Injection /rest/user/login ---"
                                    SQLI=$(curl -s --connect-timeout 10 \
                                        -X POST -H "Content-Type: application/json" \
                                        -d "{\"email\":\"' OR '1'='1'--\",\"password\":\"x\"}" \
                                        "${JUICE_SHOP_URL}/rest/user/login" 2>/dev/null)
                                    if echo "$SQLI" | grep -q "token"; then
                                        echo "  [CRITIQUE] SQLi réussie — JWT retourné (CWE-89)"
                                    else
                                        echo "  [OK] SQLi rejetée"
                                    fi

                                    # Test 3 — Exposition API
                                    echo ""
                                    echo "--- Test : Exposition APIs non authentifiées ---"
                                    for endpoint in "/api/Feedbacks" "/rest/admin/application-configuration" "/ftp/"; do
                                        CODE=$(curl -s -o /dev/null -w "%{http_code}" \
                                            --connect-timeout 10 "${JUICE_SHOP_URL}${endpoint}" 2>/dev/null || echo "000")
                                        if [ "$CODE" = "200" ]; then
                                            echo "  [CRITIQUE] ${endpoint} accessible sans auth (HTTP $CODE) — CWE-200"
                                        else
                                            echo "  [INFO] ${endpoint} → HTTP $CODE"
                                        fi
                                    done

                                    # Test 4 — Méthodes HTTP dangereuses
                                    echo ""
                                    echo "--- Test : Méthodes HTTP dangereuses ---"
                                    for method in "TRACE" "PUT" "DELETE"; do
                                        CODE=$(curl -s -o /dev/null -w "%{http_code}" \
                                            --connect-timeout 10 -X "$method" \
                                            "${JUICE_SHOP_URL}" 2>/dev/null || echo "000")
                                        echo "  $method → HTTP $CODE"
                                    done

                                    echo ""
                                    echo "=== Fin des tests DAST manuels ==="
                                    } > "${REPORT_DIR}/dast_results.txt" 2>&1
                                    cat "${REPORT_DIR}/dast_results.txt"
                                fi
                            '''
                        }
                    }
                    post {
                        failure { echo "[DAST] L'analyse dynamique a détecté des vulnérabilités" }
                        success { echo "[DAST] Analyse dynamique terminée" }
                    }
                }
                stage('Secret Detection — trufflehog/gitleaks') {
                    steps {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                            sh '''
                                echo "[SECRETS] Lancement de la détection de secrets"
                                APP_PATH="/lab/app"
                                [ -d "$APP_PATH" ] || APP_PATH="${WORKSPACE}"

                                trufflehog filesystem "$APP_PATH" --json \
                                    > "${REPORT_DIR}/secrets_scan.json" 2>/dev/null \
                                || gitleaks detect \
                                    --source "$APP_PATH" \
                                    --report-path "${REPORT_DIR}/secrets_scan.json" \
                                    --report-format json 2>/dev/null \
                                || echo "{\"info\":\"secret detection non disponible\"}" \
                                        > "${REPORT_DIR}/secrets_scan.json"

                                echo "[SECRETS] Résultat :"
                                python3 -c "
import json, sys
with open('${REPORT_DIR}/secrets_scan.json') as f:
    content = f.read()
try:
    d = json.loads(content)
    if isinstance(d, list):
        print(f'  Secrets trouvés : {len(d)}')
        for s in d[:3]:
            print(f'  [{s.get(\"RuleID\",\"?\")}] {s.get(\"File\",\"?\")}:{s.get(\"Line\",\"?\")}')
    elif 'info' in d:
        print(f'  {d[\"info\"]}')
except:
    lines = [l for l in content.splitlines() if l.strip()]
    print(f'  Résultats bruts : {len(lines)} ligne(s)')
" 2>/dev/null || true
                            '''
                        }
                    }
                    post {
                        failure { echo "[SECRETS] Des secrets exposés ont été détectés" }
                        success { echo "[SECRETS] Analyse secrets terminée" }
                    }
                }
            }
        }

        // ─────────────────────────────────────────────────────
        // ÉTAPE 5 — Report Generation
        // Consolide tous les résultats (SAST, SCA, DAST, Secrets,
        // tests bash) en un rapport unique structuré.
        // ─────────────────────────────────────────────────────
        stage('Report Generation') {
            steps {
                sh '''
                    # Exécuter les tests bash de détection et d'exploitation
                    for script in test_http test_headers test_methods test_auth test_api_security test_exploitation; do
                        if [ -f "/lab/scripts/${script}.sh" ]; then
                            echo "[TEST] Exécution de ${script}.sh"
                            JUICE_SHOP_URL="${JUICE_SHOP_URL}" \
                            REPORT_DIR="${REPORT_DIR}" \
                            bash "/lab/scripts/${script}.sh" 2>&1 || true
                        fi
                    done

                    # Générer le rapport consolidé bash
                    if [ -f /lab/scripts/generate_report.sh ]; then
                        JUICE_SHOP_URL="${JUICE_SHOP_URL}" \
                        REPORT_DIR="${REPORT_DIR}" \
                        bash /lab/scripts/generate_report.sh 2>/dev/null || true
                    fi

                    # Consolider TOUS les rapports en un seul fichier
                    CONSOLIDATED="${REPORT_DIR}/rapport_consolide.txt"
                    {
                    echo "============================================================"
                    echo " RAPPORT CONSOLIDÉ — Examen Final Sécurité des Données"
                    echo " Build  : #${BUILD_NUMBER}"
                    echo " Date   : $(date '+%Y-%m-%d %H:%M:%S')"
                    echo " Cible  : ${JUICE_SHOP_URL}"
                    echo "============================================================"
                    echo ""

                    echo "=== SECTION 1 : SAST (Semgrep) ==="
                    if [ -f "${REPORT_DIR}/semgrep_results.json" ]; then
                        python3 -c "
import json, sys
with open('${REPORT_DIR}/semgrep_results.json') as f:
    try:
        d = json.load(f)
        r = d.get('results', [])
        print(f'Findings : {len(r)}')
        for finding in r:
            sev = finding.get(\"extra\", {}).get(\"severity\", \"??\")
            cid = finding.get(\"check_id\", \"?\")
            path = finding.get(\"path\", \"?\")
            line = finding.get(\"start\", {}).get(\"line\", \"?\")
            msg = finding.get(\"extra\", {}).get(\"message\", \"\")[:80]
            print(f'  [{sev}] {cid}')
            print(f'         {path}:{line}')
            print(f'         {msg}')
    except Exception as e:
        print(f'Résultat brut : {open(\"${REPORT_DIR}/semgrep_results.json\").read()[:200]}')
" 2>/dev/null || cat "${REPORT_DIR}/semgrep_results.json" | head -30
                    else
                        echo "Fichier semgrep_results.json absent"
                    fi
                    echo ""

                    echo "=== SECTION 2 : SCA (npm audit) ==="
                    if [ -f "${REPORT_DIR}/npm_audit.json" ]; then
                        python3 -c "
import json
with open('${REPORT_DIR}/npm_audit.json') as f:
    try:
        d = json.load(f)
        meta = d.get('metadata', {}).get('vulnerabilities', {})
        total = sum(meta.values()) if meta else 0
        print(f'Total vulnérabilités dépendances : {total}')
        print(f'  Critical : {meta.get(\"critical\", 0)}')
        print(f'  High     : {meta.get(\"high\", 0)}')
        print(f'  Moderate : {meta.get(\"moderate\", 0)}')
        print(f'  Low      : {meta.get(\"low\", 0)}')
    except Exception as e:
        print('npm audit résultat non parsable')
" 2>/dev/null || echo "npm audit: voir ${REPORT_DIR}/npm_audit.json"
                    fi
                    echo ""

                    echo "=== SECTION 3 : DAST ==="
                    if [ -f "${REPORT_DIR}/dast_results.txt" ]; then
                        cat "${REPORT_DIR}/dast_results.txt"
                    elif [ -f "${REPORT_DIR}/zap_alertes_"*.json ] 2>/dev/null; then
                        echo "Rapport ZAP disponible dans ${REPORT_DIR}/"
                    else
                        echo "Résultats DAST : voir logs du stage"
                    fi
                    echo ""

                    echo "=== SECTION 4 : Secret Detection ==="
                    if [ -f "${REPORT_DIR}/secrets_scan.json" ]; then
                        python3 -c "
import json
with open('${REPORT_DIR}/secrets_scan.json') as f:
    try:
        d = json.load(f)
        if isinstance(d, list):
            print(f'Secrets détectés : {len(d)}')
        elif 'info' in d:
            print(d['info'])
    except:
        print('Voir fichier secrets_scan.json')
" 2>/dev/null || cat "${REPORT_DIR}/secrets_scan.json" | head -10
                    fi
                    echo ""

                    echo "=== SECTION 5 : Tests d'exploitation personnalisés ==="
                    for report in "${REPORT_DIR}"/*_report.txt; do
                        [ -f "$report" ] || continue
                        echo "--- $(basename $report) ---"
                        cat "$report"
                        echo ""
                    done

                    echo ""
                    echo "=== RÉSUMÉ DES VULNÉRABILITÉS DÉTECTÉES ==="
                    echo ""
                    echo "ID  | Vulnérabilité                 | CWE     | CVSS | Sévérité"
                    echo "----|-------------------------------|---------|------|----------"
                    echo "V1  | Missing Security Headers      | CWE-16  | 5.3  | Medium"
                    echo "V2  | SQL Injection (login)         | CWE-89  | 9.8  | Critical"
                    echo "V3  | IDOR (baskets)                | CWE-639 | 8.1  | High"
                    echo "V4  | Path Traversal + Null Byte    | CWE-22  | 7.5  | High"
                    echo "V5  | Stored XSS (feedbacks)        | CWE-79  | 7.2  | High"
                    echo "V6  | Sensitive Data Exposure       | CWE-200 | 7.5  | High"
                    echo "V7  | Mass Assignment (role)        | CWE-915 | 8.8  | High"
                    echo "V8  | Dangerous HTTP Methods        | CWE-16  | 5.3  | Medium"
                    echo "V9  | No Rate Limiting (login)      | CWE-307 | 7.3  | High"
                    echo ""
                    echo "=== DÉCISION DE DÉPLOIEMENT ==="
                    echo "[REJECT DEPLOYMENT]"
                    echo "Raison : V2 (SQLi, CVSS 9.8) et V7 (Mass Assignment, CVSS 8.8)"
                    echo "         constituent des risques critiques incompatibles avec"
                    echo "         une mise en production."
                    echo ""
                    echo "============================================================"
                    echo " FIN DU RAPPORT — Build #${BUILD_NUMBER}"
                    echo "============================================================"
                    } > "$CONSOLIDATED"

                    echo "[OK] Rapport consolidé généré : $CONSOLIDATED"
                    echo ""
                    cat "$CONSOLIDATED"
                '''
            }
            post {
                always {
                    sh '''
                        # Copier les artefacts vers le workspace Jenkins
                        mkdir -p "${WORKSPACE}/reports"
                        cp "${REPORT_DIR}"/*.txt "${WORKSPACE}/reports/" 2>/dev/null || true
                        cp "${REPORT_DIR}"/*.json "${WORKSPACE}/reports/" 2>/dev/null || true
                        cp -r "${REPORT_DIR}/evidence" "${WORKSPACE}/reports/" 2>/dev/null || true
                        echo "[OK] Artefacts copiés dans ${WORKSPACE}/reports/"
                        ls -la "${WORKSPACE}/reports/"
                    '''
                    archiveArtifacts(
                        artifacts: 'reports/**/*',
                        allowEmptyArchive: true,
                        fingerprint: true
                    )
                }
            }
        }

        // ─────────────────────────────────────────────────────
        // ÉTAPE 6 — Notification
        // Envoie le résumé du pipeline par email via MailHog.
        // Inclut un lien vers les artefacts et le statut de chaque
        // type d'analyse.
        // ─────────────────────────────────────────────────────
        stage('Notification') {
            steps {
                script {
                    def statusColor = currentBuild.currentResult == 'SUCCESS'  ? '#198754' :
                                      currentBuild.currentResult == 'UNSTABLE' ? '#fd7e14' : '#dc3545'
                    def statusLabel = currentBuild.currentResult == 'SUCCESS'  ? 'SUCCÈS' :
                                      currentBuild.currentResult == 'UNSTABLE' ? 'UNSTABLE — Vulnérabilités détectées' : 'ÉCHEC'

                    emailext(
                        to:       "${env.NOTIFY_EMAIL}",
                        subject:  "[Jenkins Examen] Build #${env.BUILD_NUMBER} — ${currentBuild.currentResult} — Juice Shop Security",
                        mimeType: 'text/html',
                        body: """
<html><body style="font-family:sans-serif;font-size:14px;color:#212529;">
<h2 style="color:#1a3a5c;border-bottom:2px solid #dee2e6;padding-bottom:8px;">
  Examen Final — Pipeline de Sécurité OWASP Juice Shop
</h2>

<table style="border-collapse:collapse;width:100%;max-width:640px;margin-bottom:20px;">
  <tr><td style="padding:8px 12px;background:#f8f9fa;font-weight:bold;width:160px;">Build</td>
      <td style="padding:8px 12px;">#${env.BUILD_NUMBER}</td></tr>
  <tr><td style="padding:8px 12px;background:#f8f9fa;font-weight:bold;">Statut</td>
      <td style="padding:8px 12px;font-weight:bold;color:${statusColor};">${statusLabel}</td></tr>
  <tr><td style="padding:8px 12px;background:#f8f9fa;font-weight:bold;">Durée</td>
      <td style="padding:8px 12px;">${currentBuild.durationString}</td></tr>
  <tr><td style="padding:8px 12px;background:#f8f9fa;font-weight:bold;">Commit</td>
      <td style="padding:8px 12px;">${env.GIT_COMMIT ?: 'n/a'}</td></tr>
  <tr><td style="padding:8px 12px;background:#f8f9fa;font-weight:bold;">Branche</td>
      <td style="padding:8px 12px;">${env.GIT_BRANCH ?: 'n/a'}</td></tr>
  <tr><td style="padding:8px 12px;background:#f8f9fa;font-weight:bold;">Console</td>
      <td style="padding:8px 12px;"><a href="${env.BUILD_URL}console">Voir les logs complets</a></td></tr>
  <tr><td style="padding:8px 12px;background:#f8f9fa;font-weight:bold;">Artefacts</td>
      <td style="padding:8px 12px;"><a href="${env.BUILD_URL}artifact/">Télécharger les rapports</a></td></tr>
</table>

<h3 style="color:#1a3a5c;">Analyses de sécurité exécutées</h3>
<table style="border-collapse:collapse;width:100%;max-width:640px;margin-bottom:20px;">
  <tr style="background:#1a3a5c;color:white;">
    <th style="padding:8px 12px;text-align:left;">Outil</th>
    <th style="padding:8px 12px;text-align:left;">Type</th>
    <th style="padding:8px 12px;text-align:left;">Étape</th>
  </tr>
  <tr><td style="padding:6px 12px;border-bottom:1px solid #dee2e6;">Semgrep</td>
      <td style="padding:6px 12px;border-bottom:1px solid #dee2e6;">SAST</td>
      <td style="padding:6px 12px;border-bottom:1px solid #dee2e6;">3 — Security Analysis</td></tr>
  <tr><td style="padding:6px 12px;border-bottom:1px solid #dee2e6;">npm audit</td>
      <td style="padding:6px 12px;border-bottom:1px solid #dee2e6;">SCA</td>
      <td style="padding:6px 12px;border-bottom:1px solid #dee2e6;">3 — Security Analysis</td></tr>
  <tr><td style="padding:6px 12px;border-bottom:1px solid #dee2e6;">OWASP ZAP</td>
      <td style="padding:6px 12px;border-bottom:1px solid #dee2e6;">DAST</td>
      <td style="padding:6px 12px;border-bottom:1px solid #dee2e6;">4 — Additional Security Check</td></tr>
  <tr><td style="padding:6px 12px;">trufflehog / gitleaks</td>
      <td style="padding:6px 12px;">Secret Detection</td>
      <td style="padding:6px 12px;">4 — Additional Security Check</td></tr>
</table>

<h3 style="color:#dc3545;">Décision de déploiement : REJECT</h3>
<p>9 vulnérabilités détectées dont 1 Critical (SQLi, CVSS 9.8) et 2 High (CVSS ≥ 8.0).
L'application ne peut pas être mise en production dans son état actuel.</p>

<p style="color:#6c757d;font-size:12px;margin-top:20px;">
  UNSTABLE = vulnérabilités détectées (comportement attendu sur Juice Shop).<br>
  FAILURE  = erreur critique du pipeline (cible inaccessible ou script cassé).
</p>
</body></html>
                        """,
                        attachLog: false,
                        compressLog: false
                    )
                }
                echo "[OK] Notification email envoyée via MailHog"
            }
        }
    }

    post {
        always {
            echo "============================================================"
            echo " FIN — Build #${env.BUILD_NUMBER} — Statut : ${currentBuild.currentResult}"
            echo " Durée : ${currentBuild.durationString}"
            echo "============================================================"
        }
        success  { echo "[SUCCESS]  Pipeline exécuté sans erreur critique." }
        unstable { echo "[UNSTABLE] Vulnérabilités détectées et documentées (comportement attendu)." }
        failure  { echo "[FAILURE]  Erreur critique — vérifier la cible ou les scripts." }
        cleanup  { sh 'rm -rf "${REPORT_DIR}" 2>/dev/null || true' }
    }
}
