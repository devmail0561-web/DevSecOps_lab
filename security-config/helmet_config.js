// ============================================================
// Remédiation V1 — Missing Security Headers
// Vulnérabilité : CWE-16 (Configuration), OWASP A05:2021
// CVSS           : 5.3 (Medium)
// Problème       : Juice Shop ne configure pas les en-têtes
//                  Strict-Transport-Security, Content-Security-Policy
//                  ni Referrer-Policy dans ses réponses HTTP.
// Preuve (TEST 02) :
//   [MANQUANT] Strict-Transport-Security
//   [MANQUANT] Content-Security-Policy
//   [MANQUANT] Referrer-Policy
//
// Solution : intégrer helmet.js dans le server.ts de Juice Shop
//            avant toute définition de route.
// ============================================================

'use strict'

const helmet = require('helmet')

/**
 * Applique les en-têtes de sécurité HTTP à l'application Express.
 * À appeler dans server.ts immédiatement après `const app = express()`.
 *
 * @param {import('express').Application} app
 */
function applySecurityHeaders(app) {
  app.use(
    helmet({

      // ── Content-Security-Policy ───────────────────────────
      // Empêche l'exécution de scripts non autorisés (XSS).
      // Juice Shop est une SPA Angular : les ressources statiques
      // sont toutes servies depuis la même origine.
      contentSecurityPolicy: {
        directives: {
          defaultSrc:  ["'self'"],
          scriptSrc:   ["'self'"],
          styleSrc:    ["'self'", "'unsafe-inline'"],  // Angular injecte du CSS inline
          imgSrc:      ["'self'", "data:", "blob:"],
          connectSrc:  ["'self'"],
          fontSrc:     ["'self'"],
          objectSrc:   ["'none'"],   // interdire Flash/Java
          frameSrc:    ["'none'"],   // interdire les iframes (protection clickjacking)
          mediaSrc:    ["'self'"],
          workerSrc:   ["'self'", "blob:"],
          manifestSrc: ["'self'"],
          baseUri:     ["'self'"],
          formAction:  ["'self'"],
        },
      },

      // ── HTTP Strict Transport Security ───────────────────
      // Force les connexions HTTPS pendant 1 an.
      // Empêche les attaques de type SSL-strip et downgrade.
      hsts: {
        maxAge:            31536000,  // 1 an en secondes
        includeSubDomains: true,
        preload:           true,
      },

      // ── Referrer-Policy ───────────────────────────────────
      // Limite les informations envoyées dans l'en-tête Referer
      // lors de navigations cross-origin.
      referrerPolicy: {
        policy: 'strict-origin-when-cross-origin',
      },

      // ── X-Content-Type-Options ────────────────────────────
      // Empêche le MIME-sniffing du navigateur.
      // Valeur imposée : "nosniff"
      xContentTypeOptions: true,

      // ── X-Frame-Options ───────────────────────────────────
      // Protège contre le clickjacking en interdisant les iframes.
      xFrameOptions: { action: 'deny' },

      // ── X-XSS-Protection ─────────────────────────────────
      // Désactivé intentionnellement : l'en-tête est obsolète
      // depuis Chrome 78 et peut introduire des failles XSS
      // dans certains navigateurs. La vraie défense est CSP.
      xXssProtection: false,

      // ── Permissions-Policy ────────────────────────────────
      // Désactive les fonctionnalités sensibles non nécessaires.
      permittedCrossDomainPolicies: false,
    })
  )

  // Supprimer l'en-tête X-Powered-By (révèle la technologie)
  app.disable('x-powered-by')
}

module.exports = applySecurityHeaders

// ── Usage ─────────────────────────────────────────────────
// Dans server.ts (Juice Shop), après `const app = express()` :
//
//   const applySecurityHeaders = require('./security-config/helmet_config')
//   applySecurityHeaders(app)
//
// ── Vérification ──────────────────────────────────────────
// Après redémarrage de l'application :
//
//   curl -I http://localhost:3000 | grep -E 'Strict-Transport|Content-Security|Referrer-Policy'
//
// Résultat attendu :
//   Content-Security-Policy: default-src 'self'; ...
//   Referrer-Policy: strict-origin-when-cross-origin
//   Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
