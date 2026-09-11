// ============================================================
// Remédiation V10 — JWT Algorithm None Bypass
// Vulnérabilité : CWE-347 (Improper Verification of Cryptographic Signature)
// OWASP         : A02:2021 — Cryptographic Failures
// CVSS          : 8.2 (High)
// Découverte    : HDWP scan 11/09/2026 — plugin core.session_property.jwt
//                 Expériences EXP-4a7bd886, EXP-4d948905, EXP-83c9e2a2
//
// Problème : jwt.verify() accepte alg="none", permettant de forger
//            des tokens sans clé de signature.
// Solution : forcer algorithms: ['RS256'] dans toutes les vérifications JWT.
// ============================================================

'use strict'

const jwt = require('jsonwebtoken')
const fs = require('fs')

// Clé publique RSA utilisée par Juice Shop pour signer les JWT
const publicKey = fs.readFileSync('encryptionkeys/jwt.pub', 'utf8')

/**
 * Vérifie un token JWT en forçant l'algorithme RS256.
 * Rejette automatiquement :
 *   - alg: "none"  → forge sans signature
 *   - alg: "HS256" → confusion de clé (utilise la clé publique comme secret HMAC)
 *
 * @param {string} token - Le token JWT à vérifier
 * @returns {object} Le payload décodé si valide
 * @throws {JsonWebTokenError} Si le token est invalide ou utilise un algo non autorisé
 */
function verifyToken(token) {
  return jwt.verify(token, publicKey, {
    algorithms: ['RS256']
  })
}

/**
 * Middleware Express de vérification JWT sécurisée.
 * Remplace security.isAuthorized dans les routes Juice Shop.
 */
function secureJwtMiddleware(req, res, next) {
  const authHeader = req.headers.authorization
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header.' })
  }

  const token = authHeader.slice(7)

  try {
    const decoded = verifyToken(token)
    req.user = decoded
    next()
  } catch (err) {
    return res.status(401).json({
      error: 'Invalid token.',
      detail: err.message
    })
  }
}

module.exports = { verifyToken, secureJwtMiddleware }

// ── Usage ─────────────────────────────────────────────────
// Dans server.ts (Juice Shop), remplacer :
//   const { isAuthorized } = require('./lib/insecurity')
// Par :
//   const { secureJwtMiddleware: isAuthorized } = require('./remediation/jwt_fix')
//
// ── Vérification ──────────────────────────────────────────
// 1. Forger un token avec alg="none" :
//    echo '{"alg":"none","typ":"JWT"}' | base64 | tr -d '='
//    echo '{"data":{"id":1,"role":"admin"}}' | base64 | tr -d '='
//    TOKEN="<header>.<payload>."
//
// 2. Tester :
//    curl -s -H "Authorization: Bearer $TOKEN" http://localhost:3000/rest/user/whoami
//    # Attendu après patch : HTTP 401 { "error": "Invalid token." }
//
// 3. Relancer HDWP :
//    hdwp run --context juiceshop-hdwp-context.yaml --no-tui --db verify.db
//    # Attendu : 0 finding CWE-347
