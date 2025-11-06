import express from 'express';
import axios from 'axios';
import AadhaarKyc from '../models/AadhaarKyc.js';
import { auth } from '../middleware/auth.js';

const router = express.Router();

// Read KYC provider configuration from environment with safe fallbacks.
const KYC_API_BASE = process.env.KYC_API_BASE || 'https://sandbox.kycprovider.com';
const KYC_API_KEY = process.env.KYC_API_KEY || '';

function onlyDigits(value) {
  return String(value || '').replace(/\D/g, '');
}

function last4Digits(value) {
  const d = onlyDigits(value);
  return d.slice(-4);
}

// Ensure we never log full Aadhaar number
function maskAadhaarForLog(value) {
  const last4 = last4Digits(value);
  return last4 ? `********${last4}` : '********';
}

// POST /api/kyc/aadhaar/initiate
// Body: { aadhaarNumber: string, consent: boolean }
router.post('/initiate', auth, async (req, res) => {
  try {
    const aadhaarNumberRaw = req.body?.aadhaarNumber;
    const consent = Boolean(req.body?.consent);

    const aadhaarDigits = onlyDigits(aadhaarNumberRaw);
    if (!aadhaarDigits || aadhaarDigits.length !== 12) {
      return res.status(400).json({ error: 'valid 12-digit aadhaarNumber required' });
    }
    if (!consent) {
      return res.status(400).json({ error: 'user consent required' });
    }
    if (!KYC_API_KEY || !KYC_API_BASE) {
      return res.status(500).json({ error: 'KYC provider not configured' });
    }

    // Call provider initiate endpoint
    const url = `${KYC_API_BASE.replace(/\/$/, '')}/aadhaar/initiate`;
    try {
      const response = await axios.post(
        url,
        { aadhaarNumber: aadhaarDigits, consent: true },
        { headers: { Authorization: `Bearer ${KYC_API_KEY}` } },
      );

      const txnId = response?.data?.txnId
        || response?.data?.data?.txnId
        || response?.data?.transactionId
        || null;

      if (!txnId) {
        return res.status(500).json({ error: 'kyc_initiate_unexpected_response' });
      }

      // Log only masked Aadhaar
      console.info('KYC initiate OK for user', req.user?.id, maskAadhaarForLog(aadhaarDigits));
      return res.status(201).json({ txnId, message: 'OTP sent' });
    } catch (err) {
      const status = err?.response?.status || 500;
      const providerMsg = err?.response?.data?.error || err?.response?.data?.message || 'kyc_initiate_failed';
      if (status >= 400 && status < 500) {
        return res.status(400).json({ error: providerMsg });
      }
      console.error('KYC initiate error', err?.message);
      return res.status(500).json({ error: 'kyc_initiate_error' });
    }
  } catch (err) {
    console.error('initiate route error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

// POST /api/kyc/aadhaar/verify
// Body: { txnId: string, otp: string }
router.post('/verify', auth, async (req, res) => {
  try {
    const txnId = String(req.body?.txnId || '').trim();
    const otpDigits = onlyDigits(req.body?.otp);

    if (!txnId) {
      return res.status(400).json({ error: 'txnId required' });
    }
    if (!otpDigits || otpDigits.length < 4) {
      return res.status(400).json({ error: 'valid otp required' });
    }
    if (!KYC_API_KEY || !KYC_API_BASE) {
      return res.status(500).json({ error: 'KYC provider not configured' });
    }

    // Call provider verify endpoint
    const url = `${KYC_API_BASE.replace(/\/$/, '')}/aadhaar/verify`;
    try {
      const response = await axios.post(
        url,
        { txnId, otp: otpDigits },
        { headers: { Authorization: `Bearer ${KYC_API_KEY}` } },
      );

      // Normalize provider response
      const body = response?.data || {};
      const providerData = body?.data || body?.result || body || {};
      const verified = Boolean(body?.verified ?? providerData?.verified ?? true);
      if (!verified) {
        return res.status(400).json({ verified: false, error: 'verification_failed' });
      }

      // Extract user details safely
      const name = providerData?.name || providerData?.fullName || providerData?.customerName || null;
      const dobRaw = providerData?.dob || providerData?.dateOfBirth || null;
      const gender = providerData?.gender || null;
      const address = providerData?.address || providerData?.addr || null;

      const aadhaarFromProvider =
        providerData?.aadhaarNumber || providerData?.aadhaar || providerData?.maskedAadhaar || null;
      const aadhaarLast4 = last4Digits(aadhaarFromProvider);

      // Convert DOB to Date if possible
      let dob = null;
      if (dobRaw) {
        const parsed = new Date(dobRaw);
        if (!Number.isNaN(parsed.getTime())) dob = parsed;
      }

      const doc = await AadhaarKyc.findOneAndUpdate(
        { userId: req.user.id },
        {
          userId: req.user.id,
          name: name || undefined,
          dob: dob || undefined,
          gender: gender || undefined,
          address: address || undefined,
          aadhaarLast4: aadhaarLast4 || undefined,
          verified: true,
          providerTxnId: body?.txnId || providerData?.txnId || txnId,
          verificationDate: new Date(),
        },
        { upsert: true, new: true, setDefaultsOnInsert: true },
      );

      console.info('KYC verified for user', req.user?.id, `(aadhaar ****${doc.aadhaarLast4 || '----'})`);

      // Respond with verified flag and user KYC data (no sensitive data)
      return res.status(200).json({
        verified: true,
        userData: {
          userId: doc.userId,
          name: doc.name || null,
          dob: doc.dob || null,
          gender: doc.gender || null,
          address: doc.address || null,
          aadhaarLast4: doc.aadhaarLast4 || null,
          providerTxnId: doc.providerTxnId || null,
          verificationDate: doc.verificationDate || doc.updatedAt,
        },
      });
    } catch (err) {
      const status = err?.response?.status || 500;
      const providerMsg = err?.response?.data?.error || err?.response?.data?.message || 'kyc_verify_failed';
      if (status >= 400 && status < 500) {
        return res.status(400).json({ error: providerMsg });
      }
      console.error('KYC verify error', err?.message);
      return res.status(500).json({ error: 'kyc_verify_error' });
    }
  } catch (err) {
    console.error('verify route error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;

