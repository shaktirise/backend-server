import ActivationEvent from '../models/ActivationEvent.js';
import User from '../models/User.js';
import { getReferralConfig } from './referral.js';

const DAY_MS = 24 * 60 * 60 * 1000;

function near(a, b, tolerance = 100) {
  return Math.abs(Number(a || 0) - Number(b || 0)) <= tolerance;
}

export async function computeMembershipWindowFromEvents(userId) {
  const cfg = getReferralConfig();
  const regFee = cfg.registrationFeePaise;
  const renFee = cfg.renewalFeePaise;

  const regDays = parseInt(process.env.ACCOUNT_REGISTRATION_VALID_DAYS || '60', 10) || 60;
  const renDays = parseInt(process.env.ACCOUNT_RENEWAL_VALID_DAYS || '30', 10) || 30;

  const events = await ActivationEvent.find({ userId, status: 'SUCCEEDED' })
    .sort({ occurredAt: 1 })
    .lean();
  if (!events.length) return { activatedAt: null, activeUntil: null };

  let activatedAt = null;
  let activeUntil = null;

  for (const ev of events) {
    const ts = ev.occurredAt ? new Date(ev.occurredAt) : new Date();
    const amt = Math.floor(Number(ev.amountPaise || 0));
    const isReg = near(amt, regFee);
    const isRen = !isReg && amt >= renFee;
    if (!isReg && !isRen) continue;

    if (!activatedAt) activatedAt = ts;

    const addDays = isReg ? regDays : isRen ? renDays : 0;
    if (addDays <= 0) continue;

    const base = activeUntil && activeUntil.getTime() > ts.getTime() ? activeUntil : ts;
    activeUntil = new Date(base.getTime() + addDays * DAY_MS);
  }

  return { activatedAt, activeUntil };
}

export async function backfillUserMembership(userId, { save = true } = {}) {
  const user = await User.findById(userId);
  if (!user) throw new Error('user_not_found');

  const { activatedAt, activeUntil } = await computeMembershipWindowFromEvents(userId);
  if (!activatedAt || !activeUntil) {
    return { updated: false, activatedAt: null, activeUntil: null, status: user.accountStatus || 'INACTIVE' };
  }

  user.accountActivatedAt = activatedAt;
  user.accountActiveUntil = activeUntil;

  if (user.accountStatus !== 'SUSPENDED' && user.accountStatus !== 'DEACTIVATED') {
    const now = Date.now();
    user.accountStatus = activeUntil.getTime() > now ? 'ACTIVE' : 'INACTIVE';
  }

  if (save) await user.save();

  return {
    updated: true,
    activatedAt: user.accountActivatedAt,
    activeUntil: user.accountActiveUntil,
    status: user.accountStatus,
  };
}

