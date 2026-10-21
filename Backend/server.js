require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const { MONGODB_URI, FINGERPRINT_SECRET, PORT = 3000 } = process.env;
if (!MONGODB_URI || !FINGERPRINT_SECRET) {
  console.error('Set MONGODB_URI and FINGERPRINT_SECRET in .env');
  process.exit(1);
}

// ---- Collection schema --------------------------------------------------
const schema = new mongoose.Schema({
  passwordHash:   { type: String, required: true },             // bcrypt (salted)
  fingerprint:    { type: String, required: true, unique: true }, // HMAC-SHA256, blocks duplicates
  passwordLength: { type: Number, required: true },
  lengthPolicy:   { type: Number, required: true },
  strengthScore:  { type: Number, required: true },
  strengthLabel:  { type: String, enum: ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'], required: true },
  dfaAccepted:    { type: Boolean, required: true },
  createdAt:      { type: Date, default: Date.now }
});
const PasswordRecord = mongoose.model('PasswordRecord', schema);

// ---- Same DFA as the front end (re-checked here; never trust the client) --
const classOf = c => /[A-Z]/.test(c) ? 0 : /[a-z]/.test(c) ? 1 : /[0-9]/.test(c) ? 2 : 3;
function runDfa(pw, min) {
  let n = 0, f = 0;
  for (const c of pw) { n = Math.min(n + 1, min); f |= 1 << classOf(c); }
  return { accepted: n === min && f === 15, f };
}
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const RUN = new RegExp('(?:' + 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'.split('').map(c => esc(c).repeat(3)).join('|') + ')');
const grams = [];
['abcdefghijklmnopqrstuvwxyz', '0123456789', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'].forEach(s => {
  for (let i = 0; i + 3 <= s.length; i++) { const g = s.slice(i, i + 3); grams.push(g, [...g].reverse().join('')); }
});
const SEQ = new RegExp('(?:' + grams.join('|') + ')', 'i');
const COM = /(?:password|passw0rd|qwerty|admin|letmein|welcome|iloveyou|dragon|monkey|login|abc123|111111)/i;

function strength(pw, dfa) {
  const nCls = [0, 1, 2, 3].filter(i => dfa.f & (1 << i)).length;
  let score = nCls * 15 + Math.min(pw.length, 16) * 2.5;
  if (RUN.test(pw)) score -= 15;
  if (SEQ.test(pw)) score -= 12;
  if (COM.test(pw)) score -= 30;
  if (!dfa.accepted) score = Math.min(score, 60);
  score = Math.max(0, Math.min(100, Math.round(score)));
  const label = score < 25 ? 'Very weak' : score < 45 ? 'Weak' : score < 65 ? 'Fair' : score < 85 ? 'Strong' : 'Very strong';
  return { score, label };
}

// ---- App ------------------------------------------------------------------
const app = express();
app.use(express.json({ limit: '2kb' }));
app.use(express.static(path.join(__dirname, 'public'))); // put the checker HTML in ./public/index.html

app.post('/api/passwords', async (req, res) => {
  const { password, lengthPolicy } = req.body || {};
  if (typeof password !== 'string' || password.length === 0 || password.length > 128)
    return res.status(400).json({ error: 'Invalid password.' });
  if (!Number.isInteger(lengthPolicy) || lengthPolicy < 12 || lengthPolicy > 32)
    return res.status(400).json({ error: 'lengthPolicy must be an integer from 12 to 32.' });

  const dfa = runDfa(password, lengthPolicy);
  if (!dfa.accepted)
    return res.status(422).json({ error: 'Password does not satisfy the policy (DFA rejected).' });

  const { score, label } = strength(password, dfa);
  const fingerprint = crypto.createHmac('sha256', FINGERPRINT_SECRET).update(password).digest('hex');

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const doc = await PasswordRecord.create({
      passwordHash, fingerprint,
      passwordLength: password.length, lengthPolicy,
      strengthScore: score, strengthLabel: label, dfaAccepted: true
    });
    res.status(201).json({ id: doc._id, strengthScore: score, strengthLabel: label });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ error: 'This password has already been used.' });
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

mongoose.connect(MONGODB_URI)
  .then(() => PasswordRecord.init()) // make sure the unique index exists
  .then(() => app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`)))
  .catch(err => { console.error('MongoDB connection failed:', err.message); process.exit(1); });