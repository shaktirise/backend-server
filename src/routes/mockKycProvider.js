import express from 'express';
import crypto from 'crypto';

const router = express.Router();

// In-memory store for demo purposes only
// txnId -> { otp, aadhaarLast4, createdAt }
const store = new Map();

function onlyDigits(value) {
  return String(value || '').replace(/\D/g, '');
}

function last4Digits(value) {
  const d = onlyDigits(value);
  return d.slice(-4);
}

// Middleware: optional Authorization header check (accept any token if present)
router.use((req, res, next) => {
  const auth = req.headers.authorization || '';
  if (!auth) {
    // Keep it friendly for local dev: only warn, do not block
    // return res.status(401).json({ error: 'missing_authorization' });
  }
  next();
});

// POST /mock-kyc/aadhaar/initiate
// Body: { aadhaarNumber, consent }
router.post('/aadhaar/initiate', (req, res) => {
  const aadhaar = onlyDigits(req.body?.aadhaarNumber);
  const consent = Boolean(req.body?.consent);
  if (!aadhaar || aadhaar.length !== 12) {
    return res.status(400).json({ error: 'invalid_aadhaar' });
  }
  if (!consent) {
    return res.status(400).json({ error: 'consent_required' });
  }

  // Create a fake OTP and txnId
  const otp = '123456';
  const txnId = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
  store.set(txnId, { otp, aadhaarLast4: last4Digits(aadhaar), createdAt: new Date() });

  return res.status(201).json({ txnId, message: 'OTP sent' });
});

// POST /mock-kyc/aadhaar/verify
// Body: { txnId, otp }
router.post('/aadhaar/verify', (req, res) => {
  const txnId = String(req.body?.txnId || '').trim();
  const otp = onlyDigits(req.body?.otp);
  if (!txnId) return res.status(400).json({ error: 'txn_required' });
  if (!otp) return res.status(400).json({ error: 'otp_required' });

  const rec = store.get(txnId);
  if (!rec) return res.status(400).json({ error: 'invalid_txn' });

  if (otp !== rec.otp) return res.status(400).json({ error: 'invalid_otp' });

  // Provide realistic but demo data
  return res.json({
    verified: true,
    txnId,
    data: {
      name: 'Test Aadhaar User',
      dob: '1990-01-01',
      gender: 'MALE',
      address: '123, MG Road, Bengaluru, KA, 560001',
      aadhaarNumber: `XXXXXXXX${rec.aadhaarLast4}`,
      txnId,
    },
  });
});

export default router;

