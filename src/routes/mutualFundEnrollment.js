import express from 'express';
import mongoose from 'mongoose';
import MutualFundEnrollment from '../models/MutualFundEnrollment.js';

const router = express.Router();

const INVESTMENT_AMOUNT_OPTIONS = new Set(['5000-25000', '25000-100000', '100000_PLUS']);
const INVESTMENT_TYPE_OPTIONS = new Set(['SIP', 'LUMPSUM', 'GUIDANCE']);
const CONTACT_TIME_OPTIONS = new Set(['MORNING', 'AFTERNOON', 'EVENING']);

const REQUIRED_FOR_SUBMISSION = [
  'fullName',
  'dateOfBirth',
  'mobileNumber',
  'emailId',
  'panNumber',
  'city',
  'state',
  'pinCode',
  'isNewToMutualFunds',
  'approximateInvestmentAmount',
  'investmentTypeInterested',
  'preferredContactTime',
  'consentToBeContacted',
  'declarationDate',
  'signatureOrDigitalConsent',
];

function trimString(value, maxLength = 120) {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  if (!trimmed) return '';
  return trimmed.length > maxLength ? trimmed.slice(0, maxLength) : trimmed;
}

function normalizeMobileNumber(value) {
  const text = trimString(String(value || ''), 20);
  if (!text) return { value: '' };
  const digits = text.replace(/\D/g, '');
  if (!/^\d{10,15}$/.test(digits)) {
    return { error: 'invalid_mobile_number' };
  }
  return { value: digits };
}

function normalizeEmail(value) {
  const text = trimString(String(value || ''), 180).toLowerCase();
  if (!text) return { value: '' };
  if (!/.+@.+\..+/.test(text)) {
    return { error: 'invalid_email' };
  }
  return { value: text };
}

function normalizePan(value) {
  const text = trimString(String(value || ''), 12).toUpperCase();
  if (!text) return { value: '' };
  if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(text)) {
    return { error: 'invalid_pan' };
  }
  return { value: text };
}

function normalizePinCode(value) {
  const text = trimString(String(value || ''), 6);
  if (!text) return { value: '' };
  if (!/^\d{6}$/.test(text)) {
    return { error: 'invalid_pin_code' };
  }
  return { value: text };
}

function normalizeDateOfBirth(value) {
  if (!value) return { value: null };
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return { error: 'invalid_date_of_birth' };
  }
  return { value: date };
}

function normalizeBooleanField(value, allowFalse = true) {
  if (typeof value === 'boolean') {
    return { value };
  }
  const text = trimString(String(value || ''), 20).toLowerCase();
  if (!text) return { value: allowFalse ? null : false };
  if (['true', 'yes', 'y', '1', 'on'].includes(text)) return { value: true };
  if (allowFalse && ['false', 'no', 'n', '0', 'off'].includes(text)) return { value: false };
  return { error: 'invalid_boolean' };
}

function normalizeChoice(value, allowedValues) {
  if (typeof value !== 'string') return { value: '' };
  const normalized = value.trim().toUpperCase().replace(/\s+/g, '');
  if (!normalized) return { value: '' };

  const mapped = (() => {
    if (normalized === 'LUMPSUMINVESTMENT') return 'LUMPSUM';
    if (normalized === 'NEEDGUIDANCE') return 'GUIDANCE';
    return normalized;
  })();

  if (allowedValues.has(mapped)) return { value: mapped };

  const cleanAmount = normalized
    .replace(/,/g, '')
    .replace(/[^0-9+\-A-Z]/g, '');
  if (cleanAmount === '5000-25000' || cleanAmount === '25000-100000' || cleanAmount === '100000+' || cleanAmount === '100000PLUS')
    return { value: cleanAmount === '100000+' || cleanAmount === '100000PLUS' ? '100000_PLUS' : cleanAmount };

  if (mapped === 'YES' || mapped === 'NO') {
    return { value: mapped };
  }

  return { error: 'invalid_choice' };
}

function normalizeEnrollmentValues(body) {
  const result = { values: {}, errors: [] };

  [{ key: 'fullName', maxLength: 120 }, { key: 'city', maxLength: 100 }, { key: 'state', maxLength: 100 }, { key: 'signatureOrDigitalConsent', maxLength: 120 }].forEach(
    (field) => {
      if (!(field.key in body)) return;
      const value = trimString(body[field.key], field.maxLength);
      if (value) result.values[field.key] = value;
    }
  );

  const dateOfBirth = normalizeDateOfBirth(body.dateOfBirth);
  if (dateOfBirth.error) result.errors.push({ field: 'dateOfBirth', code: dateOfBirth.error });
  else if (dateOfBirth.value) result.values.dateOfBirth = dateOfBirth.value;

  const mobile = normalizeMobileNumber(body.mobileNumber);
  if (mobile.error) result.errors.push({ field: 'mobileNumber', code: mobile.error });
  else if (mobile.value) result.values.mobileNumber = mobile.value;

  const email = normalizeEmail(body.emailId);
  if (email.error) result.errors.push({ field: 'emailId', code: email.error });
  else if (email.value) result.values.emailId = email.value;

  const pan = normalizePan(body.panNumber);
  if (pan.error) result.errors.push({ field: 'panNumber', code: pan.error });
  else if (pan.value) result.values.panNumber = pan.value;

  const pinCode = normalizePinCode(body.pinCode);
  if (pinCode.error) result.errors.push({ field: 'pinCode', code: pinCode.error });
  else if (pinCode.value) result.values.pinCode = pinCode.value;

  const isNew = normalizeBooleanField(body.isNewToMutualFunds, true);
  if (isNew.error) result.errors.push({ field: 'isNewToMutualFunds', code: isNew.error });
  else if (typeof isNew.value === 'boolean') result.values.isNewToMutualFunds = isNew.value;

  const amount = normalizeChoice(body.approximateInvestmentAmount, INVESTMENT_AMOUNT_OPTIONS);
  if (amount.error) result.errors.push({ field: 'approximateInvestmentAmount', code: amount.error });
  else if (amount.value) result.values.approximateInvestmentAmount = amount.value;

  const type = normalizeChoice(body.investmentTypeInterested, INVESTMENT_TYPE_OPTIONS);
  if (type.error) result.errors.push({ field: 'investmentTypeInterested', code: type.error });
  else if (type.value) result.values.investmentTypeInterested = type.value;

  const contact = normalizeChoice(body.preferredContactTime, CONTACT_TIME_OPTIONS);
  if (contact.error) result.errors.push({ field: 'preferredContactTime', code: contact.error });
  else if (contact.value) result.values.preferredContactTime = contact.value;

  const consent = normalizeBooleanField(body.consentToBeContacted, true);
  if (consent.error) result.errors.push({ field: 'consentToBeContacted', code: consent.error });
  else if (typeof consent.value === 'boolean') result.values.consentToBeContacted = consent.value;

  if ('declarationDate' in body) {
    const declarationDate = normalizeDateOfBirth(body.declarationDate);
    if (declarationDate.error) result.errors.push({ field: 'declarationDate', code: declarationDate.error });
    else if (declarationDate.value) result.values.declarationDate = declarationDate.value;
  }

  if ('source' in body) {
    const source = trimString(body.source, 180);
    if (source) result.values.source = source;
  }

  return result;
}

function evaluateCompletion(values) {
  const completed = REQUIRED_FOR_SUBMISSION.reduce((count, key) => {
    const value = values[key];
    if (key === 'consentToBeContacted') return value === true ? count + 1 : count;
    if (key === 'isNewToMutualFunds') return typeof value === 'boolean' ? count + 1 : count;
    if (key === 'declarationDate' && value instanceof Date) return count + 1;
    return value ? count + 1 : count;
  }, 0);

  return {
    completionPercent: Math.round((completed / REQUIRED_FOR_SUBMISSION.length) * 100),
    isComplete: completed === REQUIRED_FOR_SUBMISSION.length,
  };
}

function serializeEnrollment(doc, opts = {}) {
  const completion = evaluateCompletion(doc);
  return {
    id: doc._id,
    status: doc.status || 'DRAFT',
    fullName: doc.fullName || null,
    dateOfBirth: doc.dateOfBirth || null,
    mobileNumber: doc.mobileNumber || null,
    emailId: doc.emailId || null,
    panNumber: doc.panNumber || null,
    city: doc.city || null,
    state: doc.state || null,
    pinCode: doc.pinCode || null,
    isNewToMutualFunds: doc.isNewToMutualFunds ?? null,
    approximateInvestmentAmount: doc.approximateInvestmentAmount || null,
    investmentTypeInterested: doc.investmentTypeInterested || null,
    preferredContactTime: doc.preferredContactTime || null,
    consentToBeContacted: !!doc.consentToBeContacted,
    declarationDate: doc.declarationDate || null,
    signatureOrDigitalConsent: doc.signatureOrDigitalConsent || null,
    completionPercent: completion.completionPercent,
    isComplete: completion.isComplete,
    submittedAt: doc.submittedAt || null,
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
    ...(opts.includeMetadata
      ? {
          source: doc.source || null,
          userAgent: doc.userAgent || null,
          ipAddress: doc.ipAddress || null,
        }
      : {}),
  };
}

router.post('/', async (req, res) => {
  try {
    const body = req.body || {};
    const normalized = normalizeEnrollmentValues(body);
    if (normalized.errors.length) {
      return res.status(400).json({ error: 'validation_failed', details: normalized.errors });
    }

    const finalSubmit =
      body?.finalSubmit === true || String(body?.finalSubmit).toLowerCase() === 'true';
    const completion = evaluateCompletion(normalized.values);
    if (finalSubmit && !completion.isComplete) {
      return res.status(400).json({
        error: 'incomplete_form',
        completionPercent: completion.completionPercent,
        requiredFields: REQUIRED_FOR_SUBMISSION,
      });
    }

    const now = new Date();
    const enrichment = {
      ipAddress: req.ip || '',
      ...(req.headers?.['user-agent']
        ? { userAgent: String(req.headers['user-agent']).slice(0, 200) }
        : {}),
    };

    const enrollmentId = (() => {
      const rawId = body.enrollmentId || body._id || req.query?.enrollmentId;
      return mongoose.Types.ObjectId.isValid(rawId) ? new mongoose.Types.ObjectId(rawId) : null;
    })();

    const basePayload = {
      ...normalized.values,
      ...enrichment,
    };

    let doc;
    let statusCode = 201;
    if (enrollmentId) {
      const existing = await MutualFundEnrollment.findById(enrollmentId);
      if (!existing) return res.status(404).json({ error: 'enrollment_not_found' });

      const nextStatus = finalSubmit && completion.isComplete ? 'SUBMITTED' : existing.status || 'DRAFT';
      const setPayload = {
        ...basePayload,
        status: nextStatus,
        ...(finalSubmit && completion.isComplete && nextStatus === 'SUBMITTED'
          ? { submittedAt: now }
          : {}),
      };
      doc = await MutualFundEnrollment.findByIdAndUpdate(enrollmentId, { $set: setPayload }, { new: true });
      statusCode = 200;
    } else {
      const setPayload = {
        ...basePayload,
        status: finalSubmit && completion.isComplete ? 'SUBMITTED' : 'DRAFT',
        ...(finalSubmit && completion.isComplete ? { submittedAt: now } : {}),
      };
      doc = await MutualFundEnrollment.create(setPayload);
    }

    return res.status(statusCode).json({
      status: finalSubmit ? 'submitted' : 'saved',
      enrollment: serializeEnrollment(doc),
    });
  } catch (err) {
    console.error('mutual fund enrollment save error', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

router.get('/:enrollmentId', async (req, res) => {
  try {
    const enrollmentId = mongoose.Types.ObjectId.isValid(req.params.enrollmentId)
      ? new mongoose.Types.ObjectId(req.params.enrollmentId)
      : null;
    if (!enrollmentId) return res.status(400).json({ error: 'invalid_enrollment_id' });

    const doc = await MutualFundEnrollment.findById(enrollmentId).lean();
    if (!doc) return res.status(404).json({ error: 'enrollment_not_found' });

    return res.json({ enrollment: serializeEnrollment(doc, { includeMetadata: true }) });
  } catch (err) {
    console.error('mutual fund enrollment get error', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

export default router;
