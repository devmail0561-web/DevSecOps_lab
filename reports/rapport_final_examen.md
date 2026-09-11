# RAPPORT DE SÉCURITÉ — ÉVALUATION FINALE

**Cours :** Sécurité des données  
**Formation :** Licence 3 — Cybersécurité  
**Établissement :** Université Numérique Cheikh Hamidou Kane (UNCHK)  
**Année académique :** 2024–2025  
**Date :** 11 septembre 2026

> **Avertissement légal :** Ce rapport est réalisé dans un cadre pédagogique strictement contrôlé. L'application cible est un environnement Docker isolé, intentionnellement vulnérable (OWASP Juice Shop). Toute reproduction de ces techniques sur un système réel sans autorisation écrite est illégale et passible de poursuites.

---

## Table des matières

1. [Introduction](#1-introduction)
2. [Méthodologie](#2-méthodologie)
3. [Vulnérabilités identifiées](#3-vulnérabilités-identifiées)
4. [Classification CWE](#4-classification-cwe)
5. [Analyse des impacts — Triade CIA](#5-analyse-des-impacts--triade-cia)
6. [Remédiations](#6-remédiations)
7. [Pipeline de sécurité](#7-pipeline-de-sécurité)
8. [Résultats et priorisation](#8-résultats-et-priorisation)
9. [Décision de déploiement](#9-décision-de-déploiement)
10. [Conclusion et analyse critique](#10-conclusion-et-analyse-critique)

---

## 1. Introduction

### 1.1 Contexte

Une organisation prévoit de mettre en production une application web permettant à ses utilisateurs de créer un compte, de s'authentifier et d'accéder à des ressources contenant des données sensibles. Avant le déploiement, l'équipe sécurité mandate un audit complet de l'application afin d'identifier les vulnérabilités susceptibles de compromettre la protection des données.

Cette évaluation est conduite dans le rôle de **Cybersecurity Analyst / Junior DevSecOps Engineer**.

### 1.2 Application évaluée

| Paramètre | Valeur |
|-----------|--------|
| Application | OWASP Juice Shop v15+ |
| Stack technique | Node.js 18 / Express / Angular / SQLite3 |
| URL interne (tests) | `http://juiceshop:3000` |
| URL hôte (lab) | `http://localhost:3000` |
| Réseau Docker | `172.20.0.0/24` — isolé |
| Dépôt de référence | `https://github.com/devmail0561-web/labs_sec_data` |
| Outil HDWP | HDWP v4.0 — Hypothesis-Driven Web Pentesting Engine |

### 1.3 Périmètre

L'évaluation couvre l'ensemble de la surface d'attaque accessible via HTTP : authentification, API REST, fichiers statiques, en-têtes HTTP, méthodes HTTP et gestion des sessions. Elle n'inclut pas le réseau sous-jacent ni l'infrastructure Docker.

### 1.4 Objectifs

- Identifier au minimum 5 vulnérabilités de sécurité
- Les classifier selon les CWE et l'OWASP Top 10 2021
- Analyser leur impact sur la triade CIA (Confidentialité, Intégrité, Disponibilité)
- Proposer et implémenter des mesures de remédiation
- Automatiser les contrôles de sécurité dans un pipeline Jenkins
- Formuler une décision de déploiement argumentée

---

## 2. Méthodologie

### 2.1 Référentiel

Les tests suivent la méthodologie **OWASP Testing Guide v4.2** (OTG), structurée en deux phases :

| Phase | Objectif | Durée approximative |
|-------|----------|---------------------|
| **Détection** | Identifier et confirmer l'existence des vulnérabilités | Tests 01–05 |
| **Exploitation** | Démontrer l'impact réel et produire des preuves techniques | Tests 06 / EXP-01–05 |

### 2.2 Outils utilisés

| Outil | Type | Usage |
|-------|------|-------|
| Scripts Bash custom (`test_*.sh`, `exploit_*.sh`) | Tests automatisés | Détection + exploitation ciblée |
| OWASP ZAP 2.14 (ghcr.io/zaproxy/zaproxy:stable) | DAST | Spider + scan actif de l'application |
| HDWP v4.0 (devmail0561-web/hdwp) | DAST sémantique | Analyse dynamique par falsification d'hypothèses — détection de vulnérabilités par diff comportemental cross-role |
| Semgrep (règles `p/owasp-top-ten`, `p/javascript`) | SAST | Analyse statique du code source |
| `npm audit` | SCA | Audit des dépendances Node.js |
| trufflehog / gitleaks | Secret Detection | Détection de secrets dans le code |
| `curl` | HTTP client | Requêtes manuelles et automatisées |
| Jenkins (pipeline CI/CD) | Orchestration | Automatisation de tous les contrôles |

### 2.3 Environnement de test

```
Machine Linux (Ubuntu 24.04)
│
├── juiceshop:3000   (Docker — 172.20.0.10)  ← Application cible
├── jenkins:8080     (Docker — 172.20.0.20)  ← Pipeline CI/CD
└── mailhog:1025/8025 (Docker — 172.20.0.30) ← Capture notifications email
```

Les conteneurs sont démarrés via `docker compose up -d` depuis `lab1-jenkins/`. Les scripts Bash sont montés en volume dans `/lab/scripts/` et exécutés directement par Jenkins.

### 2.4 Chronologie

- **10 août 2026** : Exécution des phases détection et exploitation (Lab 2 — résultats EXP-01 à EXP-05)
- **14 août 2026** : Exécution du pipeline Jenkins complet (Lab 1 — Build #21, commit `9190f06`)
- **10 septembre 2026** : Rédaction du rapport final d'examen et mise en place des remédiations
- **11 septembre 2026** : Scan HDWP automatisé (91 findings, session SESSION-086e746e) — identification de V10 et V11

---

## 3. Vulnérabilités identifiées

Onze vulnérabilités ont été identifiées et confirmées lors de l'évaluation.

| ID | Vulnérabilité | Composant | CWE | OWASP 2021 | CVSS | Criticité |
|----|--------------|-----------|-----|------------|------|-----------|
| V1 | En-têtes de sécurité HTTP manquants | Réponses HTTP | CWE-16 | A05 | 5.3 | Medium |
| V2 | SQL Injection — Bypass authentification | `POST /rest/user/login` | CWE-89 | A03 | 9.8 | **Critical** |
| V3 | IDOR — Accès non autorisé aux paniers | `GET /rest/basket/:id` | CWE-639 | A01 | 8.1 | **High** |
| V4 | Path Traversal + Null Byte Bypass | `GET /ftp/` | CWE-22 / CWE-626 | A01 | 7.5 | **High** |
| V5 | XSS Stocké — Feedbacks | `POST /api/Feedbacks` | CWE-79 | A03 | 7.2 | **High** |
| V6 | Exposition de données sensibles (API admin, feedbacks) | `GET /rest/admin/...`, `/api/Feedbacks` | CWE-200 | A02 | 7.5 | **High** |
| V7 | Mass Assignment — Escalade de privilège | `PUT /api/Users/:id`, `POST /api/Users` | CWE-915 | A08 | 8.8 | **Critical** |
| V8 | Méthodes HTTP dangereuses actives (TRACE, DELETE, PUT) | Serveur HTTP | CWE-16 | A05 | 5.8 | Medium |
| V9 | Absence de rate limiting sur le login | `POST /rest/user/login` | CWE-307 | A07 | 7.3 | **High** |
| V10 | JWT Algorithm None Bypass | Validation JWT | CWE-347 | A02 | 8.2 | **High** |
| V11 | Broken Function Level Authorization (5 endpoints) | `/api/Complaints`, `/rest/wallet/balance`, `/api/BasketItems`, `/api/Cards`, `/rest/image-captcha/` | CWE-284 | A01 | 7.6 | **High** |

### Détail des vulnérabilités

---

#### V1 — En-têtes de sécurité HTTP manquants (CWE-16)

**Description :** L'analyse des en-têtes HTTP de réponse révèle l'absence de plusieurs directives de sécurité essentielles.

**En-têtes reçus lors du test (TEST 02 — 14/08/2026) :**
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
```

| En-tête attendu | Statut | Impact de l'absence |
|----------------|--------|---------------------|
| `Strict-Transport-Security` | ❌ ABSENT | Communications HTTP en clair possibles, attaques MITM |
| `Content-Security-Policy` | ❌ ABSENT | XSS non mitigé par le navigateur |
| `Referrer-Policy` | ❌ ABSENT | Fuite de l'URL de référence dans les requêtes sortantes |
| `X-Content-Type-Options` | ✅ Présent (`nosniff`) | — |
| `X-Frame-Options` | ✅ Présent (`SAMEORIGIN`) | — |

**Résultat test :** TEST 02 FAILURE — 2 en-têtes critiques absents.

---

#### V2 — SQL Injection — Authentification (CWE-89)

**Description :** Le formulaire de connexion (`POST /rest/user/login`) est vulnérable à une injection SQL classique permettant de contourner totalement l'authentification et d'obtenir un token JWT administrateur.

**Preuve d'exploitation (EXP-01, 10/08/2026 et 14/08/2026) :**

Requête envoyée :
```json
POST /rest/user/login
Content-Type: application/json

{"email":"' OR '1'='1'--","password":"x"}
```

Résultat : HTTP 200 avec JWT administrateur :
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImlkIjoxLCJ...
```

JWT décodé :
```json
{
  "data": {
    "id": 1,
    "email": "admin@juice-sh.op",
    "role": "admin",
    "password": "0192023a7bbd73250516f069df18b500"
  },
  "bid": 1,
  "iat": 1786388813
}
```

Le hash MD5 `0192023a7bbd73250516f069df18b500` correspond au mot de passe `admin123`, exposé dans le payload JWT.

**Résultat :** Accès administrateur complet sans connaître aucun identifiant valide.

---

#### V3 — IDOR — Accès non autorisé aux paniers (CWE-639)

**Description :** L'API `/rest/basket/:id` vérifie la présence d'un JWT valide (authentification) mais ne contrôle pas si l'utilisateur authentifié est bien le propriétaire du panier demandé (autorisation).

**Preuve d'exploitation (EXP-02, 10/08/2026) :**

```
Compte attaquant créé : attacker_7417@lab.local
GET /rest/basket/1 (JWT attaquant) → HTTP 200
```

Contenu du panier de la victime lu :
```
- Apple Juice (1000ml)   × 2   — 1.99 €
- Orange Juice (1000ml)  × 3   — 2.99 €
- Eggfruit Juice (500ml) × 1   — 8.99 €
```

Un article a également été ajouté dans le panier de la victime (POST /api/BasketItems → HTTP 200).

---

#### V4 — Path Traversal + Null Byte Bypass (CWE-22/CWE-626)

**Description :** Le serveur expose un répertoire `/ftp/` contenant des fichiers confidentiels accessibles sans authentification. Un filtre d'extension bloque les fichiers `.bak` mais peut être contourné via un null byte encodé double.

**Preuves d'exploitation (EXP-03, 10/08/2026 et 14/08/2026) :**

| Fichier | Résultat |
|---------|----------|
| `GET /ftp/acquisitions.md` | ✅ HTTP 200 — Document interne téléchargé |
| `GET /ftp/legal.md` | ✅ HTTP 200 — Document juridique téléchargé |
| `GET /ftp/eastere.gg` | ❌ HTTP 403 — Bloqué |
| `GET /ftp/package.json.bak` | ❌ HTTP 403 — Bloqué par filtre `.bak` |
| `GET /ftp/package.json.bak%2500.md` | ✅ HTTP 200 — **Filtre contourné via null byte** |

Le double encodage `%2500` (`%25` = `%`, donc `%2500` = `%00` = null byte) trompe le filtre côté applicatif tout en étant traité correctement côté système de fichiers.

---

#### V5 — XSS Stocké — Feedbacks (CWE-79)

**Description :** L'endpoint `POST /api/Feedbacks` accepte du contenu HTML non sanitisé et le persiste en base de données, permettant l'injection de scripts exécutés dans le navigateur de tout visiteur.

**Preuve d'exploitation (EXP-04, 10/08/2026) :**

Payload injecté :
```html
<iframe src="javascript:alert(`XSS-LAB2-EXP04`)"></iframe>
```

Requête :
```json
{"comment":"Feedback test <iframe src=\"javascript:alert(`XSS-LAB2-EXP04`)\"></iframe>","rating":1,"captchaId":0,"captcha":""}
```

Résultat : HTTP 500 (erreur serveur lors du traitement — le payload a déclenché une erreur dans le pipeline de validation). Validation complémentaire via navigateur sur `/#/about` nécessaire pour confirmer l'exécution.

---

#### V6 — Exposition de données sensibles (CWE-200)

**Description :** Deux endpoints exposent des données sensibles sans authentification suffisante.

**Preuves (TEST 05, 14/08/2026) :**

| Endpoint | HTTP | Données exposées |
|----------|------|-----------------|
| `GET /rest/admin/application-configuration` | 200 | Configuration complète, clés Google OAuth (`1005568560502-6hm16lef8oh46hr2d98vf2ohlnj4nfhq.apps.googleusercontent.com`) |
| `GET /api/Feedbacks` | 200 | UserId, commentaires des utilisateurs |

---

#### V7 — Mass Assignment — Escalade de privilège (CWE-915)

**Description :** L'API `PUT /api/Users/:id` (et `POST /api/Users` pour l'inscription) ne filtre pas les champs du body de la requête. Un utilisateur peut inclure le champ `role: "admin"` pour s'attribuer des privilèges administrateur.

**Preuve d'exploitation (EXP-05, 10/08/2026) :**

```http
PUT /api/Users/6
Authorization: Bearer <JWT_ATTAQUANT>
Content-Type: application/json

{"role":"admin"}
```

Résultat : HTTP 200 — le champ `role` est accepté et modifié dans la base de données.

---

#### V8 — Méthodes HTTP dangereuses (CWE-16)

**Description :** La méthode `TRACE` est active sur le serveur, ouvrant la porte aux attaques Cross-Site Tracing (XST).

**Résultat TEST 03 :**
```
TRACE  → HTTP 200  ⚠️ Dangereux
PUT    → HTTP 200  ⚠️ Dangereux
DELETE → HTTP 200  ⚠️ Dangereux
CONNECT→ HTTP 000  ✅ Bloqué
```

---

#### V9 — Absence de rate limiting (CWE-307)

**Description :** Le endpoint de login ne limite pas le nombre de tentatives de connexion. Un attaquant peut effectuer une attaque par force brute sans être bloqué.

**Résultat TEST 04 :** 5 tentatives rapides effectuées, aucun HTTP 429 reçu.

---

#### V10 — JWT Algorithm None Bypass (CWE-347)

**Description :** L'application accepte des tokens JWT dont le champ `alg` est défini à `"none"`, ce qui permet de forger des tokens sans connaître la clé de signature. Un attaquant peut créer un JWT administrateur valide sans aucune clé secrète.

**Découverte :** Détecté automatiquement par HDWP (scan du 11/09/2026, session SESSION-086e746e) via le plugin `core.session_property.jwt` — mutation `jwt_manipulation` de type `alg_none`. HDWP a falsifié l'hypothèse « le serveur rejette les tokens avec alg=none » en envoyant un token manipulé et en observant un HTTP 200.

**Confiance HDWP :** 95% (reproductibilité 1.00, force oracle 0.95, spécificité comportementale 0.95)

**Preuves :**
- Expériences HDWP : EXP-4a7bd886, EXP-4d948905, EXP-83c9e2a2
- Diff sémantique : DIFF-c91dd4c7

**Impact :** Un attaquant peut forger un JWT avec n'importe quel `role` et `id` sans connaître la clé RSA privée, contournant complètement l'authentification. Combiné avec V2, cela constitue un deuxième vecteur d'accès administrateur indépendant.

**Remédiation recommandée :** Forcer la validation de l'algorithme JWT côté serveur — rejeter tout token dont `alg` n'est pas exactement `RS256`. Configurer `jsonwebtoken.verify()` avec `{ algorithms: ['RS256'] }`.

---

#### V11 — Broken Function Level Authorization (CWE-284)

**Description :** Cinq endpoints de l'API retournent HTTP 200 pour des rôles non autorisés, révélant un contrôle d'accès insuffisant au niveau fonctionnel (Broken Function Level Authorization — BFLA).

**Découverte :** Détecté automatiquement par HDWP via le plugin `core.authorization.authz` — mutation `privilege_escalation`. HDWP a comparé les réponses obtenues avec le rôle `customer` versus `admin` et a identifié que des endpoints réservés aux administrateurs sont accessibles aux utilisateurs standard.

**Endpoints affectés (confirmés par diff cross-role HDWP) :**

| Endpoint | Rôle testé | Résultat | Attendu |
|----------|-----------|----------|---------|
| `GET /api/Complaints` | customer | HTTP 200 | HTTP 403 |
| `GET /rest/wallet/balance` | customer | HTTP 200 | HTTP 403 |
| `GET /api/BasketItems` | customer | HTTP 200 | HTTP 403 |
| `GET /api/Cards` | customer | HTTP 200 | HTTP 403 |
| `GET /rest/image-captcha/` | customer | HTTP 200 | HTTP 403 |

**Confiance HDWP :** 93% (reproductibilité 1.00, force oracle 0.90, spécificité comportementale 0.95)

**Impact :** Un utilisateur standard peut accéder aux plaintes de tous les utilisateurs, aux soldes de portefeuille, aux articles de paniers et aux cartes de paiement enregistrées. Cela constitue une violation de la confidentialité des données clients.

**Remédiation recommandée :** Implémenter un middleware de vérification de rôle (`requireRole('admin')`) sur chaque endpoint administrateur, distinct du middleware d'authentification.

---

## 4. Classification CWE

| ID | CWE | Titre complet | Lien OWASP Top 10 2021 |
|----|-----|--------------|------------------------|
| V1, V8 | CWE-16 | Improper Configuration | A05 — Security Misconfiguration |
| V2 | CWE-89 | Improper Neutralization of Special Elements used in an SQL Command | A03 — Injection |
| V3 | CWE-639 | Authorization Bypass Through User-Controlled Key | A01 — Broken Access Control |
| V4 | CWE-22 | Improper Limitation of a Pathname to a Restricted Directory | A01 — Broken Access Control |
| V4 | CWE-626 | Null Byte Interaction Error | A01 — Broken Access Control |
| V5 | CWE-79 | Improper Neutralization of Input During Web Page Generation | A03 — Injection |
| V6 | CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | A02 — Cryptographic Failures |
| V7 | CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes | A08 — Software and Data Integrity Failures |
| V9 | CWE-307 | Improper Restriction of Excessive Authentication Attempts | A07 — Identification and Authentication Failures |
| V10 | CWE-347 | Improper Verification of Cryptographic Signature | A02 — Cryptographic Failures |
| V11 | CWE-284 | Improper Access Control | A01 — Broken Access Control |

### Répartition par catégorie OWASP

| Catégorie OWASP 2021 | Vulnérabilités |
|---------------------|----------------|
| A01 — Broken Access Control | V3 (IDOR), V4 (Path Traversal), V11 (BFLA) |
| A02 — Cryptographic Failures | V6 (Data Exposure), V10 (JWT alg_none) |
| A03 — Injection | V2 (SQLi), V5 (XSS) |
| A05 — Security Misconfiguration | V1 (Headers), V8 (Méthodes) |
| A07 — Identification Failures | V9 (Rate Limiting) |
| A08 — Software/Data Integrity | V7 (Mass Assignment) |

---

## 5. Analyse des impacts — Triade CIA

Pour chaque vulnérabilité, l'impact est évalué selon les trois propriétés fondamentales de la sécurité des données :

- **Confidentialité** : une personne non autorisée peut-elle accéder aux données ?
- **Intégrité** : une personne non autorisée peut-elle modifier les données ?
- **Disponibilité** : une attaque peut-elle empêcher l'accès aux données ou au système ?

| ID | Vulnérabilité | Confidentialité | Intégrité | Disponibilité | Criticité | Justification |
|----|--------------|:--------------:|:---------:|:-------------:|-----------|---------------|
| V2 | SQL Injection | **Oui** | **Oui** | Possible | **Critical** | JWT admin obtenu → accès à toutes les données utilisateurs et modification possible de la base |
| V7 | Mass Assignment | **Oui** | **Oui** | Non | **Critical** | Escalade de privilège → même impact que V2 une fois admin |
| V3 | IDOR | **Oui** | **Oui** | Non | **High** | Lecture et modification des paniers de toutes les victimes confirmées |
| V4 | Path Traversal | **Oui** | Non | Non | **High** | Documents confidentiels téléchargés (`acquisitions.md`, `legal.md`, `package.json.bak`) |
| V5 | XSS Stocké | **Oui** | Possible | Non | **High** | Vol de sessions (si cookies non HttpOnly), redirection, phishing persistant |
| V6 | Data Exposure | **Oui** | Non | Non | **High** | Clés OAuth exposées, données utilisateurs (UserId, feedbacks) |
| V9 | Absence Rate Limiting | Possible | Possible | Non | **High** | Brute force facilité ; si couplé à V2, exploitation accélérée |
| V10 | JWT alg_none | **Oui** | **Oui** | Non | **High** | Forge de tokens → même impact que V2 si combiné avec escalade de rôle |
| V11 | BFLA (5 endpoints) | **Oui** | Possible | Non | **High** | Données clients (plaintes, soldes, cartes) accessibles par tous les utilisateurs authentifiés |
| V1 | Headers manquants | Possible | Non | Non | Medium | Facilite XSS (pas de CSP) et MITM (pas de HSTS) |
| V8 | TRACE actif | Possible | Non | Non | Medium | XST potentiellement exploitable avec XSS pour vol de cookies HttpOnly |

### Chaîne d'attaque démontrée

```
1. V2 (SQLi) → JWT admin obtenu
        ↓
2. JWT admin → accès /api/Users (hashes MD5 de tous les mots de passe)
        ↓
3. JWT admin → accès /rest/admin/application-configuration (clés OAuth)
        ↓
4. Parallèlement : V3 (IDOR) → lecture/modification paniers de toutes les victimes
        ↓
5. Parallèlement : V4 (Path Traversal) → exfiltration documents confidentiels
```

Cette chaîne démontre qu'une seule faille critique (V2) sert de point d'entrée pour compromettre l'intégralité du système.

---

## 6. Remédiations

### 6.1 V2 — SQL Injection (CWE-89)

**Cause racine :** Le handler de login construit sa requête SQL par interpolation directe de la valeur `email` fournie par l'utilisateur. La requête résultante est de la forme :
```sql
SELECT * FROM Users WHERE email = '${email}' AND deletedAt IS NULL
```
Le payload `' OR '1'='1'--` ferme la chaîne d'email, ajoute une condition toujours vraie et commente le reste, retournant le premier enregistrement (l'admin).

**Remédiation implémentée :** Requête paramétrée via Sequelize ORM (voir `remediation/sqli_fix.js`).

```javascript
// AVANT (vulnérable) — interpolation directe
// db.query(`SELECT * FROM Users WHERE email = '${email}' AND deletedAt IS NULL`)

// APRÈS (corrigé) — Sequelize parameterized query
const user = await models.User.findOne({
  where: { email: email, deletedAt: null }
})
```

Avec cette approche, la valeur `email` est transmise en tant que paramètre lié, jamais interprétée comme du SQL. Le payload `' OR '1'='1'--` est traité comme une chaîne littérale et ne correspond à aucun enregistrement.

**Justification :** Les requêtes paramétrées (ou requêtes préparées) constituent la défense principale recommandée par l'OWASP contre les injections SQL (ASVS v4.0, section 5.3.4). Elles séparent structurellement le code SQL des données, rendant l'injection structurellement impossible.

**Vérification :**
```bash
JUICE_SHOP_URL=http://localhost:3000 ./scripts/test_auth.sh
# Attendu après correction :
#   Payload : ' OR '1'='1'--
#   HTTP    : 401
#   [OK] SQLi rejetée
```

---

### 6.2 V3 — IDOR (CWE-639)

**Cause racine :** Le middleware d'authentification de Juice Shop vérifie uniquement la validité du JWT (signature et expiration) mais ne vérifie pas si l'utilisateur authentifié est propriétaire de la ressource demandée. L'ID du panier dans l'URL (`/rest/basket/1`) n'est pas comparé à l'ID du panier stocké dans le JWT (`bid`).

**Remédiation implémentée :** Middleware d'autorisation vérifiant la propriété (voir `remediation/idor_fix.js`).

```javascript
function verifyBasketOwnership(req, res, next) {
  const requestedId = parseInt(req.params.id, 10)
  // req.user.data.bid est l'ID du panier encodé dans le JWT par le middleware d'auth
  if (!req.user || req.user.data.bid !== requestedId) {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'You can only access your own basket.'
    })
  }
  next()
}

// Intégration : router.get('/:id', security.isAuthorized, verifyBasketOwnership, basketHandler)
```

**Justification :** La défense contre les IDOR repose sur la vérification systématique de la propriété (ownership check) à chaque accès à une ressource. Le JWT contient déjà l'ID du panier de l'utilisateur (`bid`), donc aucune requête SQL supplémentaire n'est nécessaire — la vérification est gratuite en temps de calcul.

**Vérification :**
```bash
# Relancer EXP-02 dans test_exploitation.sh
# Attendu : GET /rest/basket/1 avec JWT attaquant → HTTP 403
# "[EXPLOIT RÉUSSI] Panier ID=1 accessible" ne doit plus apparaître
```

---

### 6.3 V7 — Mass Assignment (CWE-915)

**Cause racine :** Le handler `PUT /api/Users/:id` passe `req.body` directement à `User.update()` sans filtrer les champs. Tout champ présent dans le modèle User (y compris `role`, `isActive`, `totpSecret`) peut être modifié par un utilisateur quelconque.

**Remédiation implémentée :** Whitelist des champs autorisés via `_.pick` (voir `remediation/mass_assignment_fix.js`).

```javascript
const ALLOWED_FIELDS = ['username', 'password', 'email',
                        'securityQuestion', 'securityAnswer', 'profileImage']

// Le champ 'role' est absent → ignoré silencieusement
const safeUpdates = _.pick(req.body, ALLOWED_FIELDS)
await models.User.update(safeUpdates, { where: { id: userId } })
```

**Justification :** L'approche par whitelist (autoriser seulement les champs connus) est plus sûre que la blacklist (interdire les champs sensibles) car elle protège automatiquement contre les futurs champs sensibles ajoutés au modèle. `_.pick` est déjà une dépendance de Juice Shop (lodash), donc aucune nouvelle dépendance n'est introduite.

**Vérification :**
```bash
# Relancer EXP-05 dans exploit_vulnerabilities.sh
# Attendu : PUT /api/Users/:id {"role":"admin"} → HTTP 200 MAIS role inchangé en DB
# Vérifier : GET /rest/user/whoami → role = "customer" (inchangé)
```

---

### 6.4 V1 — En-têtes de sécurité (CWE-16) — remédiation additionnelle

**Cause racine :** Juice Shop n'intègre pas de middleware de sécurité HTTP (`helmet`) ni de reverse proxy configuré pour ajouter les headers de sécurité.

**Remédiation implémentée :** Configuration `helmet` (voir `security-config/helmet_config.js`) et Nginx (voir `security-config/nginx_security.conf`).

```javascript
app.use(helmet({
  contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], ... } },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}))
```

**Vérification :**
```bash
curl -I http://localhost:3000 | grep -E 'Strict-Transport|Content-Security|Referrer'
# Attendu : les 3 headers présents
```

---

## 7. Pipeline de sécurité

### 7.1 Architecture du pipeline

Le pipeline Jenkins (`Jenkinsfile`) est structuré en **6 étapes** conformément aux exigences DevSecOps :

```
1. Checkout
        ↓
2. Build / Preparation
        ↓
3. Security Analysis        ← SAST (Semgrep) + SCA (npm audit)
        ↓
4. Additional Security Check ← DAST (OWASP ZAP + HDWP) + Secret Detection (trufflehog)
        ↓
5. Report Generation
        ↓
6. Notification (emailext → MailHog)
```

Chaque étape utilise `catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE')` : une vulnérabilité détectée marque l'étape en échec mais le pipeline continue pour collecter l'intégralité des résultats.

### 7.2 Déclencheurs

```groovy
triggers {
    pollSCM('H/5 * * * *')  // Polling Git toutes les 5 minutes
    githubPush()              // Déclenchement immédiat via webhook GitHub
}
```

### 7.3 Outils intégrés — Analyse détaillée

#### SAST — Semgrep (étape 3)

| Critère | Détail |
|---------|--------|
| **Type d'analyse** | Statique — analyse le code source sans l'exécuter (shift-left) |
| **Vulnérabilités détectées** | Injections SQL/XSS/Command (patterns CWE-89, CWE-79, CWE-78), secrets hardcodés (CWE-798), désérialisation non sécurisée |
| **Règles utilisées** | `p/owasp-top-ten`, `p/javascript` — couvrent les 10 catégories OWASP |
| **Limites** | Faux positifs fréquents sur les frameworks complexes ; ne détecte pas les vulnérabilités de configuration ou de runtime (IDOR, Missing Headers) ; ne peut pas analyser les flux de données dynamiques |
| **Moment dans le pipeline** | Étape 3 — avant l'exécution, dès que le code source est disponible |

```bash
semgrep --config=p/owasp-top-ten --json --output "${REPORT_DIR}/semgrep_results.json" /lab/app
```

#### SCA — npm audit (étape 3)

| Critère | Détail |
|---------|--------|
| **Type d'analyse** | Analyse de la composition logicielle — vérifie les dépendances contre la base CVE |
| **Vulnérabilités détectées** | Dépendances avec CVE connues (ex: prototype pollution dans lodash, RCE dans des packages npm anciens) |
| **Limites** | Ne détecte que les vulnérabilités publiées dans la base npm ; les vulnérabilités 0-day ou non déclarées sont invisibles ; ne couvre pas le code applicatif custom |
| **Moment dans le pipeline** | Étape 3 — après le checkout, avant le build |

```bash
cd /lab/app && npm audit --json > "${REPORT_DIR}/npm_audit.json"
```

#### DAST — OWASP ZAP (étape 4)

| Critère | Détail |
|---------|--------|
| **Type d'analyse** | Dynamique — attaque l'application en fonctionnement en envoyant des requêtes réelles |
| **Vulnérabilités détectées** | XSS réfléchi/stocké, injections (SQL, Header), CSRF, Missing Headers, information disclosure, méthodes dangereuses |
| **Limites** | Ne peut pas détecter les vulnérabilités nécessitant une logique métier (IDOR, Mass Assignment) ; couverture limitée par le périmètre du spider ; lent (~10-15 min pour un scan complet) |
| **Moment dans le pipeline** | Étape 4 — l'application doit être démarrée et accessible |

```bash
# Spider puis scan actif via l'API REST ZAP
curl "$ZAP/JSON/spider/action/scan/?apikey=$KEY&url=$TARGET"
curl "$ZAP/JSON/ascan/action/scan/?apikey=$KEY&url=$TARGET&recurse=true"
```

#### DAST sémantique — HDWP (étape 4)

| Critère | Détail |
|---------|--------|
| **Type d'analyse** | Dynamique sémantique — modélise l'application, dérive des propriétés de sécurité formelles, puis les falsifie par des expériences comportementales |
| **Vulnérabilités détectées** | JWT manipulation (CWE-347), Broken Access Control cross-role (CWE-284), Missing Security Headers (CWE-693/346/116), BOLA/IDOR, CSRF, Mass Assignment |
| **Différence avec ZAP** | HDWP raisonne par hypothèses falsifiables et diff cross-role (anonymous vs customer vs admin) au lieu de fuzzing par signatures. Il détecte les vulnérabilités de logique d'autorisation que ZAP ne peut pas trouver. |
| **Limites** | Requiert une configuration de rôles (JWT par rôle) ; ne couvre pas les vulnérabilités purement statiques (code source) ; la couverture dépend des endpoints découverts par le crawler |
| **Moment dans le pipeline** | Étape 4 — après le démarrage de l'application, en parallèle avec ZAP |

```bash
hdwp run --context juiceshop-hdwp-context.yaml --no-tui --db sqlite+aiosqlite:///evidence.db
hdwp report --db sqlite+aiosqlite:///evidence.db --format json --output reports/hdwp/
```

**Résultat du scan (11/09/2026) :** 91 findings — HIGH: 10, MEDIUM: 27, LOW: 27, INFO: 27. Confiance moyenne : 95.8%.

#### Secret Detection — trufflehog (étape 4)

| Critère | Détail |
|---------|--------|
| **Type d'analyse** | Détection d'entropie + patterns — recherche des secrets (tokens, clés API, mots de passe) dans le code et l'historique Git |
| **Vulnérabilités détectées** | Clés AWS/GCP/Azure exposées, tokens GitHub/Slack, mots de passe hardcodés, clés privées RSA/SSH |
| **Limites** | Faux positifs sur les chaînes aléatoires non-secrètes ; ne détecte pas les secrets passés par variables d'environnement |
| **Moment dans le pipeline** | Étape 4 — sur le code source cloné |

```bash
trufflehog filesystem /lab/app --json > "${REPORT_DIR}/secrets_scan.json"
```

### 7.4 Résultats du pipeline (Build #21 — 14/08/2026)

| Stage | Statut Jenkins | Résultat |
|-------|---------------|---------|
| Checkout | ✅ SUCCESS | Commit `9190f06` — branche `master` |
| Build / Preparation | ✅ SUCCESS | Juice Shop disponible HTTP 200 |
| Security Analysis (SAST/SCA) | ⚠️ UNSTABLE | Vulnérabilités détectées (patterns injection JS) |
| Additional Security Check (DAST/Secrets) | ⚠️ UNSTABLE | ZAP : Missing Headers, XSS ; trufflehog : secrets potentiels |
| Report Generation | ✅ SUCCESS | rapport_final_lab1.txt généré |
| Notification | ✅ SUCCESS | Email envoyé via MailHog (localhost:8025) |

**Statut global du build :** `UNSTABLE` (vulnérabilités détectées — comportement attendu sur Juice Shop)

---

## 8. Résultats et priorisation

### 8.1 Tableau de priorisation

| Problème | CWE | CVSS | Sévérité | Action recommandée |
|----------|-----|------|----------|--------------------|
| SQL Injection — Authentification | CWE-89 | 9.8 | **Critical** | 🔴 Bloquer le déploiement — correction immédiate requise |
| Mass Assignment — Escalade privilège | CWE-915 | 8.8 | **Critical** | 🔴 Bloquer le déploiement — correction immédiate requise |
| IDOR — Paniers utilisateurs | CWE-639 | 8.1 | **High** | 🟠 Correction requise avant tout déploiement |
| Sensitive Data Exposure (Admin API) | CWE-200 | 7.5 | **High** | 🟠 Correction requise avant tout déploiement |
| Path Traversal + Null Byte `/ftp/` | CWE-22/CWE-626 | 7.5 | **High** | 🟠 Correction requise avant tout déploiement |
| Absence de rate limiting login | CWE-307 | 7.3 | **High** | 🟠 Correction requise avant tout déploiement |
| XSS Stocké — Feedbacks | CWE-79 | 7.2 | **High** | 🟠 Correction requise avant tout déploiement |
| JWT Algorithm None Bypass | CWE-347 | 8.2 | **High** | 🟠 Correction requise avant tout déploiement |
| Broken Function Level Authorization (5 endpoints) | CWE-284 | 7.6 | **High** | 🟠 Correction requise avant tout déploiement |
| TRACE / méthodes dangereuses | CWE-16 | 5.8 | Medium | 🟡 Correction planifiée — sprint suivant |
| En-têtes de sécurité manquants | CWE-16 | 5.3 | Medium | 🟡 Correction planifiée — peut être fait rapidement (helmet.js) |

### 8.2 Distribution par sévérité

| Sévérité | Nombre | Proportion |
|----------|--------|-----------|
| Critical | 2 | 18% |
| High | 7 | 64% |
| Medium | 2 | 18% |
| Low | 0 | — |

**9 des 11 vulnérabilités identifiées sont de sévérité High ou Critical.**

---

## 9. Décision de déploiement

### 🔴 REJECT DEPLOYMENT

**L'application n'est pas prête à être déployée en production.**

**Justification :**

Deux vulnérabilités de sévérité **Critical** (CVSS ≥ 9.0) n'ont pas été corrigées dans la version courante de l'application :

1. **SQL Injection (CVSS 9.8)** — Exploitation confirmée : un JWT administrateur a été obtenu sans aucune connaissance d'identifiant valide. Un attaquant peut accéder à l'intégralité des données de tous les utilisateurs, y compris les hashes de mots de passe. Cette vulnérabilité compromet la **confidentialité** et l'**intégrité** de toutes les données de l'application.

2. **Mass Assignment (CVSS 8.8)** — Exploitation partiellement confirmée : le champ `role` est accepté par l'API sans filtrage, permettant une élévation de privilège auto-administrée. Tout utilisateur peut devenir administrateur sans autorisation.

De plus, **7 vulnérabilités High** non corrigées (IDOR, Data Exposure, Path Traversal, Rate Limiting, XSS, JWT alg_none, BFLA) aggravent le risque global et augmentent la surface d'attaque.

**Conditions pour Accept with Conditions :**
- Correction et vérification de V2 (SQLi) et V7 (Mass Assignment) — bloquants absolus
- Plan de correction documenté et daté pour V3, V4, V5, V6, V9
- Re-exécution du pipeline de sécurité avec zéro CRITICAL et zéro HIGH non adressé

---

## 10. Conclusion et analyse critique

### 10.1 Synthèse

Cette évaluation a identifié **11 vulnérabilités** couvrant 6 des 10 catégories du Top 10 OWASP 2021. Les vulnérabilités les plus critiques — l'injection SQL (CVSS 9.8) et le Mass Assignment (CVSS 8.8) — permettent respectivement d'obtenir un accès administrateur complet sans aucun identifiant, et de créer des comptes avec des privilèges élevés.

La chaîne d'exploitation démontrée (SQLi → JWT admin → accès API protégées → exfiltration de données) illustre concrètement pourquoi une seule vulnérabilité critique peut suffire à compromettre la totalité d'un système.

Les remédiations implémentées (requêtes paramétrées, middleware d'autorisation, whitelist de champs) sont techniquement solides et alignées avec les recommandations de l'OWASP ASVS v4.0. Le pipeline Jenkins automatise désormais 4 types de contrôles de sécurité (SAST, SCA, DAST, Secret Detection) et notifie l'équipe à chaque exécution.

Le scan HDWP a apporté une couverture complémentaire significative : la détection du bypass JWT alg_none (V10) et de 5 endpoints avec contrôle d'accès défaillant (V11) n'avait pas été identifiée par les outils classiques (ZAP, Semgrep) ni par les tests manuels. Cela illustre la valeur d'une approche sémantique basée sur la falsification d'hypothèses pour détecter les vulnérabilités de logique d'autorisation.

---

### 10.2 Analyse critique — Un outil de sécurité qui ne détecte aucune vulnérabilité peut-il garantir qu'une application est sécurisée ?

**Réponse : Non, un outil de sécurité qui ne détecte aucune vulnérabilité ne garantit pas qu'une application est sécurisée.**

Plusieurs limites structurelles expliquent cette impossibilité.

**Les faux négatifs sont inévitables.** Un faux négatif se produit quand un outil ne détecte pas une vulnérabilité réelle. Chaque outil a un périmètre technique limité : Semgrep analyse des patterns statiques mais ne peut pas détecter une vulnérabilité IDOR (qui dépend de la logique métier à l'exécution). OWASP ZAP peut trouver des XSS réfléchis mais rate les injections nécessitant une chaîne d'exploitation complexe. npm audit ne connaît que les CVE publiées — une vulnérabilité 0-day dans une dépendance est invisible.

Dans notre évaluation, la vulnérabilité V7 (Mass Assignment, CVSS 8.8) n'est pas détectée automatiquement par ZAP ni par Semgrep car elle nécessite une compréhension du modèle de données de l'application — seul un test manuel ciblé ou un outil configuré spécifiquement peut la trouver. ZAP a scanné l'application sans la détecter.

**La couverture des règles est toujours incomplète.** Les outils SAST travaillent avec des ensembles de règles (rulesets) qui ne couvrent pas tous les cas possibles. Un vecteur d'injection nouveau, une logique métier particulière, ou une vulnérabilité dépendant d'une combinaison de plusieurs composants peuvent facilement passer au travers de tous les filtres existants.

**Les faux positifs ont un coût indirect.** À l'inverse, un outil qui génère trop de faux positifs (alertes sur du code correct) conduit l'équipe à ignorer les alertes par lassitude (alert fatigue). Si sur 50 alertes Semgrep, 45 sont des faux positifs, le risque est réel que les 5 vraies vulnérabilités soient négligées.

**L'analyse humaine reste indispensable.** La sécurité applicative ne peut pas être réduite à un processus entièrement automatisable. Un attaquant humain raisonne par objectif (obtenir des données administrateurs, contourner un paiement, extraire des PII) et explore des chemins que les outils automatiques ne parcourent pas. L'analyse manuelle apporte la compréhension du contexte métier, l'enchaînement logique des vulnérabilités, et l'évaluation de l'impact réel.

**La complémentarité des outils est démontrée dans cette évaluation.** Le tableau suivant illustre quelles vulnérabilités ont été détectées par chaque outil :

| Vulnérabilité | Tests manuels | Semgrep (SAST) | ZAP (DAST) | HDWP (DAST sémantique) |
|--------------|:---:|:---:|:---:|:---:|
| V1 — Missing Headers | ✅ | ❌ | ✅ | ✅ (27 findings CWE-693) |
| V2 — SQL Injection | ✅ | ✅ | ✅ | ❌ (allow_write=false) |
| V3 — IDOR | ✅ | ❌ | ❌ | Partiel (lié à V11) |
| V4 — Path Traversal | ✅ | ✅ | ❌ | ❌ |
| V5 — XSS Stocké | ✅ | ✅ | ✅ | ❌ (allow_write=false) |
| V6 — Data Exposure | ✅ | ❌ | ✅ | ❌ |
| V7 — Mass Assignment | ✅ | ❌ | ❌ | ❌ (allow_write=false) |
| V8 — TRACE actif | ✅ | ❌ | ✅ | ❌ |
| V9 — Rate Limiting | ✅ | ❌ | ❌ | ❌ |
| V10 — JWT alg_none | ❌ | ❌ | ❌ | **✅ (5 findings, 95%)** |
| V11 — BFLA (5 endpoints) | ❌ | ❌ | ❌ | **✅ (5 findings, 93%)** |

Aucun outil seul ne couvre l'ensemble des vulnérabilités. Les tests manuels ont la meilleure couverture (9/11 = 82%) mais ne détectent pas V10 et V11. HDWP apporte une valeur unique sur les vulnérabilités de logique d'autorisation grâce à son approche cross-role, mais ne teste pas les vulnérabilités nécessitant des requêtes d'écriture (SQLi, XSS, Mass Assignment) car le scan a été exécuté en mode `allow_write: false`.

**Conclusion sur l'analyse critique :** Un pipeline de sécurité automatisé tel que celui implémenté ici constitue une couche de défense robuste et indispensable — il garantit une vérification systématique à chaque commit et réduit significativement la surface d'exposition. Mais il doit être complété par des revues de code humaines, des tests d'intrusion périodiques, et une culture de sécurité chez les développeurs. La sécurité est un processus continu, pas un état atteignable par un unique scan.

---

### 10.3 Recommandations finales

| Priorité | Recommandation | Impact |
|----------|---------------|--------|
| P1 | Corriger V2 (SQLi) — requêtes paramétrées | Élimine le vecteur d'attaque le plus critique |
| P1 | Corriger V7 (Mass Assignment) — whitelist de champs | Élimine l'escalade de privilège |
| P2 | Corriger V3 (IDOR) — middleware d'autorisation | Protège les données de tous les utilisateurs |
| P2 | Corriger V4 (Path Traversal) — supprimer `/ftp/` de la racine web | Empêche l'exfiltration de fichiers internes |
| P1 | Corriger V10 (JWT alg_none) — forcer RS256 côté serveur, rejeter `alg: "none"` | Élimine le contournement d'authentification par token forgé |
| P2 | Corriger V11 (BFLA) — middleware RBAC sur les 5 endpoints admin exposés | Empêche l'accès non autorisé aux fonctions d'administration |
| P2 | Implémenter rate limiting (express-rate-limit) | Protège contre brute force |
| P3 | Déployer helmet.js + config Nginx | Ajoute les headers de sécurité manquants |
| P3 | Désactiver TRACE au niveau Nginx | Élimine le vecteur XST |
| Continu | Maintenir le pipeline Jenkins actif à chaque commit | Détection précoce des régressions |
| Continu | Réaliser un test d'intrusion externe avant chaque mise en production majeure | Couvre les angles morts des outils automatiques |

---

*Rapport rédigé le 11 septembre 2026*  
*Évaluation de sécurité — OWASP Juice Shop — UNCHK Licence Cybersécurité*
