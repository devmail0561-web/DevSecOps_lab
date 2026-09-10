// ============================================================
// Remédiation V7 — Mass Assignment
// CWE         : CWE-915 (Improperly Controlled Modification of
//               Dynamically-Determined Object Attributes)
// OWASP       : A08:2021 — Software and Data Integrity Failures
// CVSS        : 8.8 (High)
//
// Cause racine :
//   Le handler PUT /api/Users/:id de Juice Shop passe directement
//   req.body à User.update() sans filtrer les champs modifiables.
//   N'importe quel champ du modèle User (dont `role`, `isActive`,
//   `totpSecret`) peut être modifié par un utilisateur authentifié.
//
// Preuve d'exploitation (EXP-05, 2026-08-10) :
//   Requête  : PUT /api/Users/6
//   Body     : {"role":"admin"}
//   Token    : Bearer <JWT attaquant attacker_xxxxx@lab.local>
//   Résultat : HTTP 200 — rôle de l'utilisateur modifié en "admin"
//   Fichier  : lab2-owasp/evidence/requests/EXP05_escalation_request.txt
// ============================================================

'use strict'

const _      = require('lodash')   // Juice Shop dépend déjà de lodash
const models = require('../models/index')

// ── CODE VULNÉRABLE (comportement actuel de Juice Shop) ───
// Dans routes/userApi.ts (UserApiRouter) :
//
// router.put('/:id', security.isAuthorized, (req, res) => {
//   User.update(req.body, { where: { id: req.params.id } })
//     .then(([affectedCount]) => res.json({ status: 'success', ... }))
// })
//
// req.body peut contenir : { "role": "admin" }
// → User.update({ role: "admin" }, { where: { id: X } })
// → Escalade de privilèges sans contrôle.
// ──────────────────────────────────────────────────────────

// Champs que l'utilisateur est autorisé à modifier sur son propre profil
const ALLOWED_FIELDS = [
  'username',
  'password',
  'email',
  'securityQuestion',
  'securityAnswer',
  'profileImage',
]

// Champs explicitement interdits (présents dans le modèle User de Juice Shop)
// 'role'        — détermine les droits d'accès (admin / customer)
// 'isActive'    — active/désactive le compte
// 'totpSecret'  — secret 2FA
// 'lastLoginIp' — adresse IP de dernière connexion
// 'deletedAt'   — soft delete Sequelize

/**
 * Handler PUT /api/Users/:id sécurisé.
 * Applique une whitelist stricte des champs modifiables et
 * vérifie que l'utilisateur modifie uniquement son propre profil.
 *
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 */
async function updateUserFixed(req, res) {
  const userId = parseInt(req.params.id, 10)

  // Vérification d'identité : un utilisateur ne peut modifier
  // que son propre profil (pas celui d'un autre utilisateur)
  if (req.user.data.id !== userId) {
    return res.status(403).json({
      error:   'Forbidden',
      message: 'You can only modify your own profile.',
    })
  }

  // Whitelist — _.pick extrait uniquement les clés autorisées.
  // Tout champ non listé (ex. "role", "isActive") est silencieusement
  // ignoré, même s'il est présent dans req.body.
  const safeUpdates = _.pick(req.body, ALLOWED_FIELDS)

  if (Object.keys(safeUpdates).length === 0) {
    return res.status(400).json({
      error: 'No valid fields to update.',
    })
  }

  try {
    await models.User.update(safeUpdates, { where: { id: userId } })
    const updatedUser = await models.User.findByPk(userId, {
      // Ne pas retourner le hash du mot de passe
      attributes: { exclude: ['password', 'totpSecret'] },
    })
    return res.status(200).json({ status: 'updated', data: updatedUser })
  } catch (err) {
    return res.status(500).json({ error: 'Update failed.', detail: err.message })
  }
}

module.exports = { updateUserFixed, ALLOWED_FIELDS }

// ── Intégration dans Juice Shop ───────────────────────────
// Dans routes/userApi.ts (UserApiRouter), remplacer :
//
//   router.put('/:id', security.isAuthorized, (req, res) => {
//     User.update(req.body, { where: { id: req.params.id } })
//   })
//
// Par :
//
//   const { updateUserFixed } = require('../remediation/mass_assignment_fix')
//   router.put('/:id', security.isAuthorized, updateUserFixed)
//
// ── Vérification ──────────────────────────────────────────
// Relancer EXP-05 de exploit_vulnerabilities.sh après le patch :
//
//   JUICE_SHOP_URL=http://localhost:3001 \
//   bash lab2-owasp/scans/exploit_vulnerabilities.sh 2>&1 | grep -A8 "EXP-05"
//
// Résultat attendu :
//   PUT /api/Users/<id> {"role":"admin"} → HTTP 200
//   Vérification en base : role reste "customer"
//
// Vérification manuelle :
//   # Obtenir un JWT valide
//   JWT=$(curl -s -X POST -H "Content-Type: application/json" \
//     -d '{"email":"user@example.com","password":"password"}' \
//     http://localhost:3000/rest/user/login | jq -r '.authentication.token')
//
//   # Tenter l'escalade de privilèges
//   curl -s -X PUT -H "Content-Type: application/json" \
//     -H "Authorization: Bearer $JWT" \
//     -d '{"role":"admin"}' \
//     http://localhost:3000/api/Users/6
//
//   # Vérifier que le rôle n'a pas changé
//   curl -s -H "Authorization: Bearer $JWT" \
//     http://localhost:3000/rest/user/whoami | jq '.data.role'
//   # Résultat attendu : "customer" (inchangé)
//
// Résultat actuel (non patché) :
//   [EXPLOIT RÉUSSI] Nouveau rôle : "role":"admin"
