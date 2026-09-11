// ============================================================
// Remédiation V11 — Broken Function Level Authorization (BFLA)
// Vulnérabilité : CWE-284 (Improper Access Control)
// OWASP         : A01:2021 — Broken Access Control
// CVSS          : 7.6 (High)
// Découverte    : HDWP scan 11/09/2026 — plugin core.authorization.authz
//                 Diff cross-role : customer vs admin sur 5 endpoints
//
// Problème : les endpoints admin ne vérifient que l'authentification
//            (JWT valide) mais pas l'autorisation (rôle admin requis).
// Solution : middleware requireRole() vérifiant req.user.data.role.
// ============================================================

'use strict'

/**
 * Middleware factory : vérifie que l'utilisateur authentifié
 * possède l'un des rôles autorisés.
 *
 * @param {...string} allowedRoles - Liste des rôles autorisés (ex: 'admin', 'customer')
 * @returns {Function} Middleware Express
 *
 * @example
 *   // Endpoint réservé aux admins
 *   router.get('/api/Complaints', isAuthorized, requireRole('admin'), handler)
 *
 *   // Endpoint accessible aux customers et admins
 *   router.get('/rest/wallet/balance', isAuthorized, requireRole('customer', 'admin'), handler)
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !req.user.data || !req.user.data.role) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required.'
      })
    }

    const userRole = req.user.data.role

    if (!allowedRoles.includes(userRole)) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `Role '${userRole}' is not authorized for this endpoint. Required: ${allowedRoles.join(' or ')}.`
      })
    }

    next()
  }
}

// ── Endpoints à protéger (détectés par HDWP) ──────────────
// Ces endpoints retournaient HTTP 200 pour le rôle "customer"
// alors qu'ils devraient être restreints.
//
// Endpoint                  | Rôle requis      | Raison
// /api/Complaints           | admin            | Plaintes de tous les utilisateurs
// /rest/wallet/balance      | customer, admin  | Solde du portefeuille (propre)
// /api/BasketItems          | customer, admin  | Articles de panier (propre)
// /api/Cards                | customer, admin  | Cartes de paiement (propre)
// /rest/image-captcha/      | customer, admin  | Génération de captcha

// ── Application dans les routes Juice Shop ────────────────
//
// Dans routes/complaints.ts :
//   router.get('/', security.isAuthorized, requireRole('admin'), module.exports.getAllComplaints)
//
// Dans routes/wallet.ts :
//   router.get('/balance', security.isAuthorized, requireRole('customer', 'admin'), module.exports.getWalletBalance)
//
// Dans routes/basketItems.ts :
//   router.get('/', security.isAuthorized, requireRole('customer', 'admin'), module.exports.getBasketItems)
//   // + ajouter une vérification d'ownership (comme V3) pour ne retourner
//   //   que les items du panier de l'utilisateur connecté
//
// Dans routes/cards.ts :
//   router.get('/', security.isAuthorized, requireRole('customer', 'admin'), module.exports.getCards)
//   // + filtrer par UserId pour ne retourner que les cartes de l'utilisateur

module.exports = { requireRole }

// ── Vérification ──────────────────────────────────────────
//
// Après application du patch :
//
//   # Obtenir un JWT customer
//   JWT_CUSTOMER=$(curl -s -X POST -H "Content-Type: application/json" \
//     -d '{"email":"hdwp_user@test.local","password":"HdwpTest123!"}' \
//     http://localhost:3000/rest/user/login | \
//     python3 -c "import sys,json; print(json.load(sys.stdin)['authentication']['token'])")
//
//   # Tester les endpoints protégés
//   curl -s -o /dev/null -w "HTTP %{http_code}\n" \
//     -H "Authorization: Bearer $JWT_CUSTOMER" \
//     http://localhost:3000/api/Complaints
//   # Attendu : HTTP 403 (admin only)
//
//   curl -s -o /dev/null -w "HTTP %{http_code}\n" \
//     -H "Authorization: Bearer $JWT_CUSTOMER" \
//     http://localhost:3000/rest/wallet/balance
//   # Attendu : HTTP 200 (customer autorisé pour son propre solde)
//
// Relancer HDWP :
//   hdwp run --context juiceshop-hdwp-context.yaml --no-tui --db verify.db
//   # Attendu : 0 finding CWE-284 privilege_escalation
