// ============================================================
// Remédiation V2 — SQL Injection
// CWE         : CWE-89 (Improper Neutralization of Special
//               Elements used in an SQL Command)
// OWASP       : A03:2021 — Injection
// CVSS        : 9.8 (Critical)
//
// Cause racine :
//   Juice Shop concatène directement les entrées utilisateur
//   dans les requêtes SQL via des template literals ou l'opérateur
//   de concaténation de chaînes, permettant à un attaquant de
//   modifier la logique de la requête.
//
// Preuve d'exploitation (EXP-01, 2026-08-10) :
//   Payload : {"email":"' OR '1'='1'--","password":"x"}
//   Résultat : HTTP 200 + JWT admin retourné
//   Token    : eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...
//   Identité : admin@juice-sh.op (confirmé via /rest/user/whoami)
// ============================================================

'use strict'

const bcrypt = require('bcrypt')
const jwt    = require('jsonwebtoken')
const fs     = require('fs')
const models = require('../models/index')  // Sequelize ORM — Juice Shop

// Clé privée RSA utilisée par Juice Shop pour signer les JWT
const privateKey = fs.readFileSync('encryptionkeys/privateKey.pem', 'utf8')

// ── CODE VULNÉRABLE (ce que fait Juice Shop actuellement) ─
// Source simplifiée de routes/login.ts :
//
// db.sequelize.query(
//   `SELECT * FROM Users WHERE email = '${req.body.email}'
//    AND password = '${hash}' AND deletedAt IS NULL`,
//   { model: UserModel, plain: true }
// )
//
// Avec email = "' OR '1'='1'--", la requête devient :
//   SELECT * FROM Users WHERE email = '' OR '1'='1'-- ...
//   La condition '1'='1' est toujours vraie → retourne le premier
//   utilisateur (admin) sans vérification de mot de passe.
// ──────────────────────────────────────────────────────────

/**
 * Handler de login sécurisé — remplace le handler vulnérable.
 * Utilise l'ORM Sequelize avec une recherche par égalité stricte
 * sur l'email, éliminant toute possibilité d'injection SQL.
 *
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 */
async function loginFixed(req, res) {
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe requis.' })
  }

  // Sequelize parameterized query — Sequelize génère en interne :
  //   SELECT * FROM Users WHERE email = ? AND deletedAt IS NULL
  // Le placeholder ? est lié à la valeur `email` par le driver
  // SQLite3, qui ne l'interprète jamais comme du SQL.
  //
  // Avec email = "' OR '1'='1'--", la recherche échoue simplement
  // car aucun utilisateur n'a cet email littéral → HTTP 401.
  const user = await models.User.findOne({
    where: {
      email:     email,
      deletedAt: null,
    },
  })

  if (!user) {
    // Message d'erreur générique — ne pas distinguer
    // "email inconnu" de "mauvais mot de passe" (énumération)
    return res.status(401).json({ error: 'Invalid email or password.' })
  }

  // Comparaison du mot de passe en clair avec le hash bcrypt
  const passwordMatch = await bcrypt.compare(password, user.password)
  if (!passwordMatch) {
    return res.status(401).json({ error: 'Invalid email or password.' })
  }

  // Génération du JWT signé RS256 — structure identique à Juice Shop
  const token = jwt.sign(
    {
      data: {
        id:       user.id,
        email:    user.email,
        role:     user.role,
        bid:      user.basketId,
        uname:    user.username,
      },
    },
    privateKey,
    { algorithm: 'RS256', expiresIn: '8h' }
  )

  return res.status(200).json({
    authentication: {
      token: token,
      bid:   user.basketId,
      umail: user.email,
    },
  })
}

module.exports = { loginFixed }

// ── Intégration dans Juice Shop ───────────────────────────
// Dans routes/login.ts, remplacer le handler existant par :
//
//   const { loginFixed } = require('../remediation/sqli_fix')
//   router.post('/', loginFixed)
//
// ── Vérification ──────────────────────────────────────────
// Relancer test_auth.sh après application du patch :
//
//   JUICE_SHOP_URL=http://localhost:3000 \
//   REPORT_DIR=/tmp/verify_sqli \
//   bash scripts/test_auth.sh
//
// Résultat attendu :
//   [TEST] SQL Injection sur /rest/user/login
//     HTTP    : 401
//     [OK] SQLi rejetée
//
// Résultat actuel (non patché) :
//   [CRITICAL] SQLi réussie — JWT retourné sans credentials valides
