# Rapport HDWP — 2026-09-11 16:43 UTC

## Résumé exécutif

91 finding(s) confirmé(s) : HIGH: 10, MEDIUM: 27, LOW: 27, INFO: 27

## Findings Hauts

### FIND-fcf39238 — A02:2021 | CWE-347 | HIGH

**Endpoint :** ``  
**Confiance :** 95%  
**OWASP :** A02:2021  
**CWE :** CWE-347

**Résumé :** 1. Envoyer GET http://localhost:3000

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000
2. 2. Avec les credentials de l'attaquant
3. 3. Observer : JWT alg_none: token manipule accepte (200) -- validation JWT defaillante

**Analyse de confiance :**

| Modèle | Score |
|--------|-------|
| V1 (5D linéaire) | 95% |
| V2 (10D logistique) | 46% |

| Signal | Valeur | Poids | Contribution |
|--------|--------|-------|--------------|
| Reproductibilité | 1.00 | 1.6 | +1.60 |
| Force du verdict oracle | 0.95 | 1.3 | +1.26 |
| Spécificité comportementale | 0.95 | 0.9 | +0.88 |
| Profondeur de causalité (replays) | 0.33 | 1.0 | +0.33 |
| Qualité des observations | 0.77 | 0.3 | +0.26 |

*Principaux signaux : Reproductibilité (+1.60), Force du verdict oracle (+1.26), Spécificité comportementale (+0.88)*

**Remédiation :** Valider le token JWT avec un algorithme fixe et verifie la signature.

**Preuve :**
- Expériences : EXP-4a7bd886, EXP-4d948905, EXP-83c9e2a2
- Diffs : DIFF-c91dd4c7

---

### FIND-693373d2 — A01:2021 | CWE-284 | HIGH

**Endpoint :** `/api/Complaints`  
**Confiance :** 93%  
**OWASP :** A01:2021  
**CWE :** CWE-284

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Complaints

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Complaints
2. 2. Avec les credentials de l'attaquant
3. 3. Observer : Privilege escalation succeeded: endpoint returned 200 for unauthorized role

**Analyse de confiance :**

| Modèle | Score |
|--------|-------|
| V1 (5D linéaire) | 93% |
| V2 (10D logistique) | 48% |

| Signal | Valeur | Poids | Contribution |
|--------|--------|-------|--------------|
| Reproductibilité | 1.00 | 1.6 | +1.62 |
| Force du verdict oracle | 0.90 | 1.4 | +1.22 |
| Spécificité comportementale | 0.95 | 1.0 | +0.91 |
| Profondeur de causalité (replays) | 0.33 | 1.0 | +0.34 |
| Qualité des observations | 0.77 | 0.4 | +0.28 |

*Principaux signaux : Reproductibilité (+1.62), Force du verdict oracle (+1.22), Spécificité comportementale (+0.91)*

**Remédiation :** Implementer un controle de role explicite sur cet endpoint.

**Preuve :**
- Expériences : EXP-f173b1ed, EXP-cfd33ba5, EXP-9d8d52f3
- Diffs : DIFF-a54bfbbd

---

### FIND-494b499c — A02:2021 | CWE-347 | HIGH

**Endpoint :** ``  
**Confiance :** 95%  
**OWASP :** A02:2021  
**CWE :** CWE-347

**Résumé :** 1. Envoyer GET http://localhost:3000

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000
2. 2. Avec les credentials de l'attaquant
3. 3. Observer : JWT alg_none: token manipule accepte (200) -- validation JWT defaillante

**Analyse de confiance :**

| Modèle | Score |
|--------|-------|
| V1 (5D linéaire) | 95% |
| V2 (10D logistique) | 53% |

| Signal | Valeur | Poids | Contribution |
|--------|--------|-------|--------------|
| Reproductibilité | 1.00 | 1.7 | +1.65 |
| Force du verdict oracle | 0.95 | 1.4 | +1.31 |
| Spécificité comportementale | 0.95 | 1.0 | +0.93 |
| Profondeur de causalité (replays) | 0.33 | 1.0 | +0.34 |
| Qualité des observations | 0.77 | 0.4 | +0.29 |

*Principaux signaux : Reproductibilité (+1.65), Force du verdict oracle (+1.31), Spécificité comportementale (+0.93)*

**Remédiation :** Valider le token JWT avec un algorithme fixe et verifie la signature.

**Preuve :**
- Expériences : EXP-b67b81d5, EXP-fda9ecce, EXP-2794f1d4
- Diffs : DIFF-130e670e

---

### FIND-52e1a87f — A01:2021 | CWE-284 | HIGH

**Endpoint :** `/rest/wallet/balance`  
**Confiance :** 93%  
**OWASP :** A01:2021  
**CWE :** CWE-284

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/wallet/balance

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/wallet/balance
2. 2. Avec les credentials de l'attaquant
3. 3. Observer : Privilege escalation succeeded: endpoint returned 200 for unauthorized role

**Analyse de confiance :**

| Modèle | Score |
|--------|-------|
| V1 (5D linéaire) | 93% |
| V2 (10D logistique) | 55% |

| Signal | Valeur | Poids | Contribution |
|--------|--------|-------|--------------|
| Reproductibilité | 1.00 | 1.7 | +1.67 |
| Force du verdict oracle | 0.90 | 1.4 | +1.26 |
| Spécificité comportementale | 0.95 | 1.0 | +0.95 |
| Profondeur de causalité (replays) | 0.33 | 1.0 | +0.34 |
| Qualité des observations | 0.77 | 0.4 | +0.30 |

*Principaux signaux : Reproductibilité (+1.67), Force du verdict oracle (+1.26), Spécificité comportementale (+0.95)*

**Remédiation :** Implementer un controle de role explicite sur cet endpoint.

**Preuve :**
- Expériences : EXP-907282a9, EXP-488a3915, EXP-72f315fd
- Diffs : DIFF-a72a629c

---

### FIND-87887017 — A02:2021 | CWE-347 | HIGH

**Endpoint :** ``  
**Confiance :** 95%  
**OWASP :** A02:2021  
**CWE :** CWE-347

**Résumé :** 1. Envoyer GET http://localhost:3000

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000
2. 2. Avec les credentials de l'attaquant
3. 3. Observer : JWT alg_none: token manipule accepte (200) -- validation JWT defaillante

**Analyse de confiance :**

| Modèle | Score |
|--------|-------|
| V1 (5D linéaire) | 95% |
| V2 (10D logistique) | 55% |

| Signal | Valeur | Poids | Contribution |
|--------|--------|-------|--------------|
| Reproductibilité | 1.00 | 1.7 | +1.65 |
| Force du verdict oracle | 0.95 | 1.4 | +1.32 |
| Spécificité comportementale | 0.95 | 1.0 | +0.97 |
| Profondeur de causalité (replays) | 0.33 | 1.0 | +0.34 |
| Qualité des observations | 0.77 | 0.4 | +0.29 |

*Principaux signaux : Reproductibilité (+1.65), Force du verdict oracle (+1.32), Spécificité comportementale (+0.97)*

**Remédiation :** Valider le token JWT avec un algorithme fixe et verifie la signature.

**Preuve :**
- Expériences : EXP-8df82140, EXP-2bbd4a19, EXP-723506f7
- Diffs : DIFF-3d25e471

---

### FIND-ef6ecb83 — A02:2021 | CWE-347 | HIGH

**Endpoint :** ``  
**Confiance :** 95%  
**OWASP :** A02:2021  
**CWE :** CWE-347

**Résumé :** 1. Envoyer GET http://localhost:3000

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000
2. 2. Avec les credentials de l'attaquant
3. 3. Observer : JWT alg_none: token manipule accepte (200) -- validation JWT defaillante

**Analyse de confiance :**

| Modèle | Score |
|--------|-------|
| V1 (5D linéaire) | 95% |
| V2 (10D logistique) | 54% |

| Signal | Valeur | Poids | Contribution |
|--------|--------|-------|--------------|
| Reproductibilité | 1.00 | 1.6 | +1.65 |
| Force du verdict oracle | 0.95 | 1.4 | +1.32 |
| Spécificité comportementale | 0.95 | 1.0 | +0.99 |
| Profondeur de causalité (replays) | 0.33 | 1.0 | +0.34 |
| Qualité des observations | 0.77 | 0.4 | +0.29 |

*Principaux signaux : Reproductibilité (+1.65), Force du verdict oracle (+1.32), Spécificité comportementale (+0.99)*

**Remédiation :** Valider le token JWT avec un algorithme fixe et verifie la signature.

**Preuve :**
- Expériences : EXP-aa557912, EXP-75b7f569, EXP-f2c6dc5d
- Diffs : DIFF-6bba8066

---

### FIND-3d97014c — A01:2021 | CWE-284 | HIGH

**Endpoint :** `/rest/image-captcha/`  
**Confiance :** 93%  
**OWASP :** A01:2021  
**CWE :** CWE-284

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/image-captcha/

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/image-captcha/
2. 2. Avec les credentials de l'attaquant
3. 3. Observer : Privilege escalation succeeded: endpoint returned 200 for unauthorized role

**Analyse de confiance :**

| Modèle | Score |
|--------|-------|
| V1 (5D linéaire) | 93% |
| V2 (10D logistique) | 54% |

| Signal | Valeur | Poids | Contribution |
|--------|--------|-------|--------------|
| Reproductibilité | 1.00 | 1.7 | +1.65 |
| Force du verdict oracle | 0.90 | 1.4 | +1.26 |
| Spécificité comportementale | 0.95 | 1.1 | +1.01 |
| Profondeur de causalité (replays) | 0.33 | 1.0 | +0.34 |
| Qualité des observations | 0.77 | 0.4 | +0.29 |

*Principaux signaux : Reproductibilité (+1.65), Force du verdict oracle (+1.26), Spécificité comportementale (+1.01)*

**Remédiation :** Implementer un controle de role explicite sur cet endpoint.

**Preuve :**
- Expériences : EXP-386699f1, EXP-d767d16f, EXP-6167d05c
- Diffs : DIFF-8c701536

---

### FIND-59a9d903 — A02:2021 | CWE-347 | HIGH

**Endpoint :** ``  
**Confiance :** 95%  
**OWASP :** A02:2021  
**CWE :** CWE-347

**Résumé :** 1. Envoyer GET http://localhost:3000

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000
2. 2. Avec les credentials de l'attaquant
3. 3. Observer : JWT alg_none: token manipule accepte (200) -- validation JWT defaillante

**Analyse de confiance :**

| Modèle | Score |
|--------|-------|
| V1 (5D linéaire) | 95% |
| V2 (10D logistique) | 57% |

| Signal | Valeur | Poids | Contribution |
|--------|--------|-------|--------------|
| Reproductibilité | 1.00 | 1.7 | +1.66 |
| Force du verdict oracle | 0.95 | 1.4 | +1.34 |
| Spécificité comportementale | 0.95 | 1.1 | +1.02 |
| Profondeur de causalité (replays) | 0.33 | 1.0 | +0.34 |
| Qualité des observations | 0.77 | 0.4 | +0.30 |

*Principaux signaux : Reproductibilité (+1.66), Force du verdict oracle (+1.34), Spécificité comportementale (+1.02)*

**Remédiation :** Valider le token JWT avec un algorithme fixe et verifie la signature.

**Preuve :**
- Expériences : EXP-0f28deda, EXP-0584addd, EXP-ede80cda
- Diffs : DIFF-8dd1bf94

---

### FIND-95e307e0 — A01:2021 | CWE-284 | HIGH

**Endpoint :** `/api/BasketItems`  
**Confiance :** 93%  
**OWASP :** A01:2021  
**CWE :** CWE-284

**Résumé :** 1. Envoyer GET http://localhost:3000/api/BasketItems

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/BasketItems
2. 2. Avec les credentials de l'attaquant
3. 3. Observer : Privilege escalation succeeded: endpoint returned 200 for unauthorized role

**Analyse de confiance :**

| Modèle | Score |
|--------|-------|
| V1 (5D linéaire) | 93% |
| V2 (10D logistique) | 56% |

| Signal | Valeur | Poids | Contribution |
|--------|--------|-------|--------------|
| Reproductibilité | 1.00 | 1.7 | +1.66 |
| Force du verdict oracle | 0.90 | 1.4 | +1.28 |
| Spécificité comportementale | 0.95 | 1.1 | +1.02 |
| Profondeur de causalité (replays) | 0.33 | 1.0 | +0.34 |
| Qualité des observations | 0.77 | 0.4 | +0.30 |

*Principaux signaux : Reproductibilité (+1.66), Force du verdict oracle (+1.28), Spécificité comportementale (+1.02)*

**Remédiation :** Implementer un controle de role explicite sur cet endpoint.

**Preuve :**
- Expériences : EXP-0db04fd5, EXP-169bae13, EXP-de183fea
- Diffs : DIFF-6ca09927

---

### FIND-5ded1327 — A01:2021 | CWE-284 | HIGH

**Endpoint :** `/api/Cards`  
**Confiance :** 93%  
**OWASP :** A01:2021  
**CWE :** CWE-284

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Cards

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Cards
2. 2. Avec les credentials de l'attaquant
3. 3. Observer : Privilege escalation succeeded: endpoint returned 200 for unauthorized role

**Analyse de confiance :**

| Modèle | Score |
|--------|-------|
| V1 (5D linéaire) | 93% |
| V2 (10D logistique) | 77% |

| Signal | Valeur | Poids | Contribution |
|--------|--------|-------|--------------|
| Reproductibilité | 1.00 | 1.6 | +1.60 |
| Force du verdict oracle | 0.90 | 1.4 | +1.24 |
| Différence cross-rôle confirmée | 0.70 | 1.8 | +1.23 |
| Spécificité comportementale | 0.95 | 1.1 | +1.04 |
| Profondeur de causalité (replays) | 0.33 | 1.0 | +0.33 |

*Principaux signaux : Reproductibilité (+1.60), Force du verdict oracle (+1.24), Différence cross-rôle confirmée (+1.23)*

**Remédiation :** Implementer un controle de role explicite sur cet endpoint.

**Preuve :**
- Expériences : EXP-9cb1ff38, EXP-e88c24ec, EXP-5d52567f
- Diffs : DIFF-f78e4fba

---

## Findings Moyens

### FIND-a3682bb1 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-4d956ecc — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/ftp`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-b11dd7c8 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000//ipinfo.io`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000//ipinfo.io

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000//ipinfo.io
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-381b5ba3 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/engine.io`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/engine.io

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/engine.io
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-65ef3f7c — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/api/Products`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Products

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Products
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-87291f97 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/rest/captcha`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/captcha

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/captcha
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-fb47a849 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/api/SecurityQuestions`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/api/SecurityQuestions

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/SecurityQuestions
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-e771a937 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/rest/user/security-question?email=`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/user/security-question?email=

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/user/security-question?email=
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-0ba9bdf0 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/api/Quantitys`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Quantitys

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Quantitys
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-91ea43ae — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/api/Deliverys`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Deliverys

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Deliverys
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-08085956 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/rest/memories`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/memories

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/memories
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-7a413675 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/api/Hints`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Hints

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Hints
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-9f5e12c1 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/ftp/quarantine`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/quarantine

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/quarantine
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-0f76043b — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/ftp/acquisitions.md`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/acquisitions.md

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/acquisitions.md
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-471ceb47 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/ftp/announcement_encrypted.md`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/announcement_encrypted.md

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/announcement_encrypted.md
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-89b16339 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/ftp/incident-support.kdbx`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/incident-support.kdbx

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/incident-support.kdbx
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-6720c1e6 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/ftp/legal.md`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/legal.md

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/legal.md
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-1d6684c6 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-d3bd400c — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-d692e3ab — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-f0a334b2 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-2b4d3cca — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/api/BasketItems`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/api/BasketItems

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/BasketItems
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-7f6a1ed6 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/api/Complaints`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Complaints

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Complaints
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-997e4fdc — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/rest/image-captcha/`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/image-captcha/

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/image-captcha/
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-3f376c08 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/rest/wallet/balance`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/wallet/balance

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/wallet/balance
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-d853961b — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/api/Cards`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Cards

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Cards
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-50277e03 — A05:2021 | CWE-693 | MEDIUM

**Endpoint :** `http://localhost:3000/rest/order-history`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-693

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/order-history

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/order-history
2. 2. Observer la réponse : Content-Security-Policy absent

**Remédiation :** Ajouter le header CSP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

## Findings Bas

### FIND-3ffcdcdf — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-ce71c900 — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/ftp`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-d72372fc — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000//ipinfo.io`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000//ipinfo.io

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000//ipinfo.io
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-fba253fa — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/engine.io`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/engine.io

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/engine.io
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-12e14c67 — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/api/Products`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Products

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Products
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-dab44555 — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/rest/captcha`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/captcha

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/captcha
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-88122181 — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/api/SecurityQuestions`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/api/SecurityQuestions

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/SecurityQuestions
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-c9d28d16 — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/rest/user/security-question?email=`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/user/security-question?email=

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/user/security-question?email=
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-6b5a34a2 — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/api/Quantitys`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Quantitys

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Quantitys
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-f316e68f — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/api/Deliverys`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Deliverys

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Deliverys
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-bf1cc171 — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/rest/memories`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/memories

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/memories
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-1c5d552c — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/api/Hints`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Hints

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Hints
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-75b7974d — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/ftp/quarantine`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/quarantine

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/quarantine
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-a51bf681 — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/ftp/acquisitions.md`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/acquisitions.md

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/acquisitions.md
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-e8b53212 — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/ftp/announcement_encrypted.md`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/announcement_encrypted.md

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/announcement_encrypted.md
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-586391db — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/ftp/incident-support.kdbx`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/incident-support.kdbx

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/incident-support.kdbx
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-2ce36b7e — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/ftp/legal.md`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/legal.md

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/legal.md
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-aa29e1cf — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-f85df55b — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-3a810684 — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-3c98b33a — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-841f1d65 — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/api/BasketItems`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/api/BasketItems

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/BasketItems
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-14f4347b — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/api/Complaints`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Complaints

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Complaints
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-ce1c5c71 — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/rest/image-captcha/`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/image-captcha/

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/image-captcha/
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-a77f5b54 — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/rest/wallet/balance`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/wallet/balance

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/wallet/balance
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-73685c14 — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/api/Cards`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Cards

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Cards
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-53017441 — A05:2021 | CWE-346 | LOW

**Endpoint :** `http://localhost:3000/rest/order-history`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-346

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/order-history

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/order-history
2. 2. Observer la réponse : Cross-Origin-Opener-Policy absent

**Remédiation :** Ajouter le header COOP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

## Findings Informationnels

### FIND-3368af3f — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-a37a54a7 — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/ftp`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-be94d9e9 — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000//ipinfo.io`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000//ipinfo.io

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000//ipinfo.io
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-03a4f27b — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/engine.io`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/engine.io

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/engine.io
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-155f2c07 — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/api/Products`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Products

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Products
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-a42bac10 — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/rest/captcha`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/captcha

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/captcha
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-2c561d6c — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/api/SecurityQuestions`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/api/SecurityQuestions

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/SecurityQuestions
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-60c48a7d — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/rest/user/security-question?email=`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/user/security-question?email=

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/user/security-question?email=
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-d2552848 — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/api/Quantitys`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Quantitys

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Quantitys
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-833bbcf7 — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/api/Deliverys`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Deliverys

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Deliverys
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-a354ca9f — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/rest/memories`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/memories

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/memories
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-e090e63f — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/api/Hints`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Hints

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Hints
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-49851ba2 — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/ftp/quarantine`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/quarantine

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/quarantine
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-de18293c — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/ftp/acquisitions.md`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/acquisitions.md

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/acquisitions.md
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-d3495ffb — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/ftp/announcement_encrypted.md`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/announcement_encrypted.md

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/announcement_encrypted.md
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-0e0abe7e — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/ftp/incident-support.kdbx`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/incident-support.kdbx

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/incident-support.kdbx
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-307b7de1 — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/ftp/legal.md`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/legal.md

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/legal.md
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-f9a51e1b — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_linux_amd_64.url
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-2f45513e — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_linux_arm_64.url
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-cb7f7d5f — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_macos_64.url
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-d712d218 — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/ftp/quarantine/juicy_malware_windows_64.exe.url
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-15feed78 — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/api/BasketItems`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/api/BasketItems

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/BasketItems
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-80dbc000 — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/api/Complaints`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Complaints

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Complaints
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-1f32f174 — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/rest/image-captcha/`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/image-captcha/

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/image-captcha/
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-388a7db5 — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/rest/wallet/balance`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/wallet/balance

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/wallet/balance
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-eb18c9ee — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/api/Cards`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/api/Cards

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/api/Cards
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

### FIND-bd4fde01 — A05:2021 | CWE-116 | INFO

**Endpoint :** `http://localhost:3000/rest/order-history`  
**Confiance :** 96%  
**OWASP :** A05:2021  
**CWE :** CWE-116

**Résumé :** 1. Envoyer GET http://localhost:3000/rest/order-history

**Étapes de reproduction :**

1. 1. Envoyer GET http://localhost:3000/rest/order-history
2. 2. Observer la réponse : Referrer-Policy absent

**Remédiation :** Ajouter le header RP dans toutes les réponses HTTP.

**Preuve :**
- Expériences : —
- Diffs : —

---

## Méthodologie

HDWP Engine v0.1.0 — Moteur de test de sécurité property-driven.  
Boucle : OBSERVE → MODEL → INFER PROPERTIES → HYPOTHESIZE → EXPERIMENT → ORACLE → FINDING
