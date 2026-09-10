# Examen Final — Sécurité des Données

**Cours :** Sécurité des données — Licence 3 Cybersécurité  
**Établissement :** Université Numérique Cheikh Hamidou Kane (UNCHK)  
**Année :** 2024–2025

> **Avertissement :** Ce projet est réalisé dans un cadre pédagogique contrôlé. L'environnement est entièrement local et isolé. Toute reproduction sur un système réel sans autorisation est illégale.

---

## Présentation

Ce dépôt contient l'évaluation de sécurité complète de l'application **OWASP Juice Shop**, réalisée dans le cadre de l'examen final du cours Sécurité des données. Il couvre :

- L'identification de 9 vulnérabilités (SQLi, IDOR, XSS, Mass Assignment, Path Traversal, etc.)
- L'analyse d'impact selon la triade CIA
- Les remédiations implémentées pour les vulnérabilités critiques
- Un pipeline Jenkins automatisant SAST, SCA, DAST et Secret Detection
- La décision de déploiement argumentée

---

## Architecture

```
Machine Linux
│
├── juiceshop:3000   (Docker — 172.20.0.10)  ← Application cible (Juice Shop)
├── jenkins:8080     (Docker — 172.20.0.20)  ← Orchestrateur CI/CD
└── mailhog:8025     (Docker — 172.20.0.30)  ← Capture des notifications email
```

Réseau Docker isolé : `172.20.0.0/24`

---

## Prérequis

- Docker Engine ≥ 24.0
- Docker Compose v2
- Accès internet pour le pull des images (premier lancement)
- Jenkins avec les plugins : `email-ext`, `git`, `pipeline`

---

## Lancement rapide

### 1. Démarrer l'environnement

```bash
cd /home/virus-one/cours_simac_l3/Semestre_6/Sec_data/projet/labs_v2/lab1-jenkins
docker compose up -d
```

Vérifier que les services sont démarrés :
```bash
docker compose ps
# juiceshop   Up   0.0.0.0:3000->3000/tcp
# jenkins     Up   0.0.0.0:8080->8080/tcp
# mailhog     Up   0.0.0.0:8025->8025/tcp
```

### 2. Accéder aux interfaces

| Service | URL | Identifiants |
|---------|-----|-------------|
| Juice Shop | http://localhost:3000 | `admin@juice-sh.op` / `admin123` |
| Jenkins | http://localhost:8080 | `admin` / `admin123` |
| MailHog (emails) | http://localhost:8025 | — |

---

## Lancement des analyses

### Option A — Via le pipeline Jenkins (recommandé)

1. Aller sur http://localhost:8080
2. Ouvrir le job **juice-shop-security**
3. Cliquer sur **Build Now**
4. Consulter la console et les artefacts après le build

Le pipeline exécute automatiquement les 6 étapes : Checkout → Build/Preparation → Security Analysis (SAST + SCA) → Additional Security Check (DAST + Secret Detection) → Report Generation → Notification.

### Option B — Scripts manuels

```bash
# Variables d'environnement
export JUICE_SHOP_URL=http://localhost:3000
export REPORT_DIR=/tmp/reports_manual
mkdir -p $REPORT_DIR/evidence

BASE=/home/virus-one/cours_simac_l3/Semestre_6/Sec_data/projet/labs_v2/lab1-jenkins/scripts

# Tests de détection
$BASE/test_http.sh          # TEST 01 — Disponibilité HTTP
$BASE/test_headers.sh       # TEST 02 — En-têtes de sécurité
$BASE/test_methods.sh       # TEST 03 — Méthodes HTTP
$BASE/test_auth.sh          # TEST 04 — Authentification + SQLi
$BASE/test_api_security.sh  # TEST 05 — Exposition des APIs

# Phase d'exploitation
$BASE/test_exploitation.sh  # TEST 06 — SQLi + IDOR + FTP + XSS

# Rapport consolidé
$BASE/generate_report.sh
```

```bash
# Exploitation complète (Lab 2)
cd /home/virus-one/cours_simac_l3/Semestre_6/Sec_data/projet/labs_v2/lab2-owasp
export JUICE_SHOP_URL=http://localhost:3001
docker compose up -d
./scans/exploit_vulnerabilities.sh
```

### Option C — Scan OWASP ZAP seul

```bash
cd /home/virus-one/cours_simac_l3/Semestre_6/Sec_data/projet/labs_v2/lab2-owasp
docker compose up -d owasp-zap
export JUICE_SHOP_URL=http://localhost:3001
export ZAP_URL=http://localhost:8091
export ZAP_API_KEY=changeme
./scans/zap_scan.sh
# Rapports générés dans : lab2-owasp/reports/
```

---

## Outils utilisés

| Outil | Type | Étape pipeline |
|-------|------|----------------|
| Semgrep (`p/owasp-top-ten`) | SAST — analyse statique | Security Analysis |
| npm audit | SCA — analyse des dépendances | Security Analysis |
| OWASP ZAP 2.14 | DAST — analyse dynamique | Additional Security Check |
| trufflehog / gitleaks | Secret Detection | Additional Security Check |
| Scripts Bash custom (`test_*.sh`) | Tests fonctionnels + exploitation | Security Analysis + Additional Check |
| MailHog | Capture SMTP locale | Notification |

---

## Structure du dépôt

```
projet_examen/
├── README.md                    ← Ce fichier
├── Jenkinsfile                  ← Pipeline CI/CD (6 étapes)
│
├── reports/
│   ├── rapport_final_examen.md  ← Rapport complet (10 sections)
│   └── rapport_final_examen.html← Version HTML imprimable en PDF
│
├── screenshots/                 ← 10 captures d'écran de l'environnement
│   ├── 01_juiceshop_accueil.png
│   ├── 02_juiceshop_login.png
│   ├── 03_jenkins_dashboard.png
│   ├── 04_jenkins_manage.png
│   ├── 05_jenkins_job_page.png
│   ├── 06_jenkins_build_console.png
│   ├── 07_jenkins_build_detail.png
│   ├── 08_jenkins_job_apres_build.png
│   ├── 09_juiceshop_ftp_directory.png
│   └── 10_juiceshop_scoreboard.png
│
├── security-config/
│   ├── helmet_config.js         ← Configuration headers HTTP (Node.js/Express)
│   └── nginx_security.conf      ← Config Nginx avec HSTS, CSP, rate limiting
│
└── remediation/
    ├── sqli_fix.js              ← Requêtes paramétrées (V2 — CWE-89)
    ├── idor_fix.js              ← Middleware d'autorisation (V3 — CWE-639)
    ├── mass_assignment_fix.js   ← Whitelist de champs (V7 — CWE-915)
    └── notes_remediation.md     ← Tableau cause/correction/vérification
```

---

## Résultats clés

| Vulnérabilité | CVSS | Statut |
|--------------|------|--------|
| SQL Injection (CWE-89) | 9.8 Critical | 🔴 Non corrigée dans Juice Shop |
| Mass Assignment (CWE-915) | 8.8 Critical | 🔴 Non corrigée dans Juice Shop |
| IDOR Paniers (CWE-639) | 8.1 High | 🔴 Non corrigée dans Juice Shop |
| Path Traversal + Null Byte (CWE-22/626) | 7.5 High | 🔴 Non corrigée dans Juice Shop |
| Sensitive Data Exposure (CWE-200) | 7.5 High | 🔴 Non corrigée dans Juice Shop |

**Décision de déploiement : 🔴 Reject Deployment**

Remédiations proposées et documentées dans `remediation/` — à appliquer sur le code source de l'application avant tout déploiement en production.

---

## Plan de la vidéo de démonstration (5–10 min)

1. **(0:00–1:30)** Présentation de l'environnement Docker (Juice Shop, Jenkins, MailHog)
2. **(1:30–3:30)** Démonstration de la vulnérabilité principale : SQLi → JWT admin (EXP-01)
3. **(3:30–5:00)** Démonstration IDOR (EXP-02) et Path Traversal (EXP-03)
4. **(5:00–7:30)** Pipeline Jenkins : lancement, résultats par étape, artefacts archivés
5. **(7:30–9:00)** Notification email reçue dans MailHog
6. **(9:00–10:00)** Décision finale : Reject Deployment — justification

---

## Références

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [Jenkins Pipeline](https://www.jenkins.io/doc/book/pipeline/)
- [Semgrep OWASP rules](https://semgrep.dev/p/owasp-top-ten)
- [OWASP ZAP](https://www.zaproxy.org/)
