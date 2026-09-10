# Notes de Remédiation — Vulnérabilités Critiques

**Examen Final Sécurité des Données — OWASP Juice Shop**
Licence 3 Cybersécurité — 2024-2025

---

## Tableau de synthèse

| Vulnérabilité | ID | CWE | Cause racine | Remédiation implémentée | Fichier | Vérification |
|---|---|---|---|---|---|---|
| Missing Security Headers | V1 | CWE-16 | Absence de middleware helmet et de proxy de sécurité | Configuration helmet.js + Nginx avec HSTS, CSP, Referrer-Policy | `security-config/helmet_config.js` `security-config/nginx_security.conf` | `curl -I http://localhost:3000 \| grep -E 'Strict-Transport\|Content-Security\|Referrer-Policy'` |
| SQL Injection | V2 | CWE-89 | Interpolation directe de l'email dans la requête SQL via template literal | Sequelize parameterized query (findOne with where clause) | `remediation/sqli_fix.js` | `JUICE_SHOP_URL=http://localhost:3000 bash scripts/test_auth.sh` → attendu HTTP 401 sur payload SQLi |
| IDOR (Paniers) | V3 | CWE-639 | Vérification du JWT sans contrôle de propriété de la ressource basket | Middleware `verifyBasketOwnership` vérifiant req.user.data.bid | `remediation/idor_fix.js` | Relancer EXP-02 → HTTP 403 attendu pour tous les paniers étrangers |
| Mass Assignment | V7 | CWE-915 | req.body passé directement à User.update() sans filtrage des champs | Whitelist `_.pick(req.body, ALLOWED_FIELDS)` excluant `role`, `isActive` | `remediation/mass_assignment_fix.js` | Relancer EXP-05 → HTTP 200 mais `role` inchangé en base |

---

## Vulnérabilité V1 — Missing Security Headers

**CWE-16 / OWASP A05:2021 / CVSS 5.3 (Medium)**

**Preuve d'exploitation :**
Résultat de `test_headers.sh` (TEST 02, 2026-08-10) :
```
[MANQUANT] [CRITICAL] Strict-Transport-Security
[MANQUANT] [CRITICAL] Content-Security-Policy
[PRÉSENT]  [CRITICAL] X-Content-Type-Options: nosniff
[PRÉSENT]  [WARNING]  X-Frame-Options: SAMEORIGIN
[MANQUANT] [WARNING]  Referrer-Policy
```
En-têtes bruts de la réponse HTTP de Juice Shop :
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
```

**Cause racine :**
Juice Shop (v15+) ne charge pas `helmet` dans sa configuration Express (`server.ts`). L'absence de HSTS permet les connexions HTTP non chiffrées et les attaques SSL-strip. L'absence de CSP supprime la principale défense contre le XSS. L'absence de Referrer-Policy expose des informations d'URL dans les requêtes cross-origin.

**Remédiation :**
Deux niveaux de correction complémentaires :
1. **Application** : intégrer `helmet_config.js` dans `server.ts` de Juice Shop pour activer HSTS (maxAge=31536000, includeSubDomains, preload), CSP (default-src 'self'), Referrer-Policy ('strict-origin-when-cross-origin').
2. **Infrastructure** : déployer `nginx_security.conf` en reverse proxy pour appliquer les headers au niveau réseau, indépendamment de l'application.

**Justification :**
La défense en couches (application + infrastructure) garantit que les headers sont présents même si l'application est mise à jour ou reconfigurée incorrectement. HSTS est particulièrement critique car, une fois reçu par le navigateur, il force toutes les connexions futures en HTTPS sans possibilité de downgrade.

**Procédure de vérification :**
```bash
# Après application de la remédiation :
curl -I http://localhost:3000 | grep -E 'Strict-Transport|Content-Security|Referrer-Policy'

# Résultat attendu :
# Content-Security-Policy: default-src 'self'; ...
# Referrer-Policy: strict-origin-when-cross-origin
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

---

## Vulnérabilité V2 — SQL Injection

**CWE-89 / OWASP A03:2021 / CVSS 9.8 (Critical)**

**Preuve d'exploitation :**
Résultat de EXP-01 (2026-08-10) :
```
Payload : {"email":"' OR '1'='1'--","password":"x"}
HTTP    : 200
[EXPLOIT RÉUSSI] JWT admin obtenu
Token   : eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImlkIjoxLCJ...
Identité: admin@juice-sh.op (confirmé via /rest/user/whoami)
```
Le payload `' OR '1'='1'--` transforme la requête SQL en :
```sql
SELECT * FROM Users WHERE email = '' OR '1'='1'-- AND deletedAt IS NULL
```
La condition `'1'='1'` est toujours vraie, retournant le premier utilisateur (admin) sans vérification du mot de passe.

**Cause racine :**
Dans `routes/login.ts`, Juice Shop construit la requête SQL en concaténant directement la valeur de `req.body.email` dans la chaîne de requête via `db.sequelize.query()` avec un template literal. Aucune sanitisation ni paramétrage n'est appliqué avant l'exécution.

**Remédiation :**
Remplacer la requête SQL brute par une requête Sequelize ORM utilisant `findOne({ where: { email: email } })`. Sequelize génère automatiquement une requête paramétrée (`SELECT * FROM Users WHERE email = ?`) où la valeur est liée par le driver SQLite3 sans interprétation SQL possible.

**Justification :**
Les requêtes paramétrées (prepared statements) séparent structurellement le code SQL des données utilisateur. Même si l'email contient des caractères SQL spéciaux (`'`, `--`, `OR`), ils sont traités comme des données littérales, jamais comme des opérateurs SQL. C'est la contre-mesure recommandée par OWASP pour CWE-89.

**Procédure de vérification :**
```bash
JUICE_SHOP_URL=http://localhost:3000 \
REPORT_DIR=/tmp/verify_sqli \
bash scripts/test_auth.sh

# Résultat attendu après patch :
#   [TEST] SQL Injection sur /rest/user/login
#     Payload : ' OR '1'='1'--
#     HTTP    : 401
#     [OK] SQLi rejetée
#   RÉSULTAT : SUCCESS

# Résultat avant patch :
#   [CRITICAL] SQLi réussie — JWT retourné sans credentials valides
#   RÉSULTAT : FAILURE
```

---

## Vulnérabilité V3 — IDOR (Insecure Direct Object Reference)

**CWE-639 / OWASP A01:2021 / CVSS 8.1 (High)**

**Preuve d'exploitation :**
Résultat de EXP-02 (2026-08-10) :
```
Compte attaquant : attacker_23568@lab.local
Requête          : GET /rest/basket/1
Authorization    : Bearer <JWT attaquant>
Résultat         : HTTP 200
Contenu          : panier de l'admin (ID=1) avec ses articles
Preuve           : captures/reports/evidence/EXP02_basket_1.json
```
L'attaquant a également pu ajouter un article dans le panier de la victime :
```
POST /api/BasketItems {"ProductId":1,"BasketId":1,"quantity":99}
Résultat : HTTP 200 — article ajouté dans le panier d'autrui
```

**Cause racine :**
Le middleware `security.isAuthorized` de Juice Shop valide uniquement la signature du JWT (authentification), sans vérifier que l'utilisateur authentifié est propriétaire de la ressource demandée (autorisation). Le handler de `/rest/basket/:id` retourne le panier correspondant à `:id` sans comparer cet ID avec le `bid` (basket ID) du token JWT de l'utilisateur.

**Remédiation :**
Insérer le middleware `verifyBasketOwnership` entre `security.isAuthorized` et le handler de route. Ce middleware compare `req.params.id` avec `req.user.data.bid` (le basket ID enregistré dans le JWT lors du login). Si les IDs ne correspondent pas, la requête est rejetée avec HTTP 403.

**Justification :**
Le JWT de Juice Shop contient le champ `bid` qui est initialisé lors de la création du compte et mis à jour à chaque login. Ce champ identifie de manière fiable le panier de l'utilisateur authentifié. La vérification ne nécessite aucune requête en base de données supplémentaire, ce qui préserve les performances.

**Procédure de vérification :**
```bash
JUICE_SHOP_URL=http://localhost:3000 \
REPORT_DIR=/tmp/verify_idor \
bash scripts/test_exploitation.sh 2>&1 | grep -A15 "EXP-02"

# Résultat attendu après patch :
#   Panier ID=1 → HTTP 403
#   Panier ID=2 → HTTP 403
#   Panier ID=3 → HTTP 403
#   [INFO] Aucun panier étranger accessible

# Résultat avant patch :
#   [EXPLOIT RÉUSSI] Panier ID=1 accessible sans en être propriétaire (HTTP 200)
```

---

## Vulnérabilité V7 — Mass Assignment

**CWE-915 / OWASP A08:2021 / CVSS 8.8 (High)**

**Preuve d'exploitation :**
Résultat de EXP-05 (2026-08-10) :
```
Compte attaquant : attacker_xxxxx@lab.local
Requête          : PUT /api/Users/<user_id>
Body             : {"role":"admin"}
Authorization    : Bearer <JWT attaquant>
HTTP             : 200
Nouveau rôle     : "admin"
Preuve           : lab2-owasp/evidence/requests/EXP05_escalation_request.txt
```

**Cause racine :**
Le handler `PUT /api/Users/:id` dans `routes/userApi.ts` passe directement `req.body` (l'objet JSON envoyé par le client) à `User.update()` sans aucun filtrage. Le modèle Sequelize `User` possède un champ `role` qui peut prendre les valeurs `"customer"` ou `"admin"`. En envoyant `{"role":"admin"}`, l'attaquant exploite l'absence de whitelist pour élever ses propres privilèges.

**Remédiation :**
Appliquer `_.pick(req.body, ALLOWED_FIELDS)` avant de passer les données à `User.update()`. La fonction `_.pick` de lodash extrait uniquement les clés explicitement listées dans `ALLOWED_FIELDS`, ignorant silencieusement tous les autres champs (dont `role`, `isActive`, `totpSecret`). Ajouter également une vérification que l'utilisateur modifie uniquement son propre profil.

**Justification :**
La whitelist (liste blanche) est plus sûre que la blacklist (liste noire) car elle ne nécessite pas de connaître à l'avance tous les champs sensibles à exclure. Si de nouveaux champs sensibles sont ajoutés au modèle `User`, ils ne seront pas modifiables par défaut.

**Procédure de vérification :**
```bash
# Étape 1 : obtenir un JWT utilisateur standard
JWT=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"email":"jim@juice-sh.op","password":"ncc-1701"}' \
  http://localhost:3000/rest/user/login | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['authentication']['token'])")

# Étape 2 : tenter l'escalade de privilèges
USER_ID=$(curl -s -H "Authorization: Bearer $JWT" \
  http://localhost:3000/rest/user/whoami | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['data']['id'])")

curl -s -X PUT -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT" \
  -d '{"role":"admin"}' \
  http://localhost:3000/api/Users/$USER_ID

# Étape 3 : vérifier que le rôle n'a pas changé
curl -s -H "Authorization: Bearer $JWT" \
  http://localhost:3000/rest/user/whoami | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print('role:', d['data']['role'])"

# Résultat attendu après patch :
#   role: customer  (inchangé)

# Résultat avant patch :
#   role: admin     (escalade réussie)
```
