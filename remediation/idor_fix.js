// ============================================================
// Remédiation V3 — Insecure Direct Object Reference (IDOR)
// CWE         : CWE-639 (Authorization Bypass Through
//               User-Controlled Key)
// OWASP       : A01:2021 — Broken Access Control
// CVSS        : 8.1 (High)
//
// Cause racine :
//   Le middleware d'authentification de Juice Shop vérifie que
//   le token JWT est valide (signature correcte, non expiré),
//   mais ne vérifie pas que l'utilisateur authentifié est bien
//   le propriétaire de la ressource demandée.
//   Un attaquant avec un JWT valide peut accéder aux paniers
//   de n'importe quel autre utilisateur en incrémentant l'ID.
//
// Preuve d'exploitation (EXP-02, 2026-08-10) :
//   Compte attaquant : attacker_23568@lab.local
//   Requête          : GET /rest/basket/1
//   Authorization    : Bearer <JWT attaquant>
//   Résultat         : HTTP 200 — contenu du panier de l'admin
//   Fichier preuve   : captures/reports/evidence/EXP02_basket_1.json
// ============================================================

'use strict'

const express = require('express')
const router  = express.Router()

// ── CODE VULNÉRABLE (comportement actuel de Juice Shop) ───
// Dans routes/basket.ts :
//
// router.get('/:id', security.isAuthorized, (req, res) => {
//   // security.isAuthorized vérifie uniquement que le JWT est valide
//   // Il ne vérifie PAS que req.params.id === req.user.data.bid
//   BasketModel.findOne({ where: { id: req.params.id }, include: [...] })
//     .then(basket => res.json({ status: 'success', data: basket }))
// })
//
// Résultat : tout utilisateur authentifié peut lire /rest/basket/1,
// /rest/basket/2, etc., quel que soit son propre panier.
// ──────────────────────────────────────────────────────────

/**
 * Middleware de vérification de propriété du panier.
 * À insérer entre security.isAuthorized et le handler de route.
 *
 * Le JWT de Juice Shop contient le champ `bid` (basket ID) dans
 * req.user.data, mis à jour à chaque login. Ce champ identifie
 * le panier appartenant à l'utilisateur connecté.
 *
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function verifyBasketOwnership(req, res, next) {
  const requestedId = parseInt(req.params.id, 10)

  // req.user est défini par le middleware JWT (security.isAuthorized)
  // req.user.data.bid est l'ID du panier inscrit dans le token
  if (!req.user || req.user.data.bid !== requestedId) {
    return res.status(403).json({
      error:   'Forbidden',
      message: 'You can only access your own basket.',
    })
  }

  next()
}

// Accès en lecture au panier
// Avant : router.get('/:id', security.isAuthorized, basketHandler)
// Après :
router.get(
  '/:id',
  require('../lib/insecurity').isAuthorized,
  verifyBasketOwnership,
  (req, res) => {
    const models = require('../models/index')
    models.Basket.findOne({
      where:   { id: req.params.id },
      include: [{ model: models.Product, paranoid: false }],
    }).then((basket) => {
      if (!basket) return res.status(404).json({ status: 'error', data: 'Not found' })
      return res.json({ status: 'success', data: basket })
    }).catch((err) => {
      return res.status(500).json({ status: 'error', data: err.message })
    })
  }
)

// Modification du panier — même protection
router.put(
  '/:id',
  require('../lib/insecurity').isAuthorized,
  verifyBasketOwnership,
  (req, res) => {
    const models = require('../models/index')
    models.Basket.update(req.body, { where: { id: req.params.id } })
      .then(() => res.json({ status: 'success' }))
      .catch((err) => res.status(500).json({ status: 'error', data: err.message }))
  }
)

module.exports = { router, verifyBasketOwnership }

// ── Pourquoi cette correction est efficace ────────────────
// Le JWT est signé avec une clé RSA privée uniquement connue
// du serveur. L'attaquant ne peut pas forger un token avec
// bid=1 pour son propre compte. Le bid du token correspond
// toujours au panier créé lors de l'inscription de l'utilisateur.
// Aucune requête en base de données supplémentaire n'est nécessaire.
//
// ── Vérification ──────────────────────────────────────────
// Relancer EXP-02 de test_exploitation.sh après le patch :
//
//   JUICE_SHOP_URL=http://localhost:3000 \
//   REPORT_DIR=/tmp/verify_idor \
//   bash scripts/test_exploitation.sh 2>&1 | grep -A5 "EXP-02"
//
// Résultat attendu :
//   Panier ID=1 → HTTP 403
//   Panier ID=2 → HTTP 403
//   ...
//   [INFO] Aucun panier IDOR abouti
//
// Résultat actuel (non patché) :
//   [EXPLOIT RÉUSSI] Panier ID=1 accessible sans en être propriétaire (HTTP 200)
