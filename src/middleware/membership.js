import User from '../models/User.js';
import { formatLocalISO, toEpochMs } from '../utils/time.js';

function buildMembershipPayloadFromUser(user) {
  const now = Date.now();
  const activatedAt = user?.accountActivatedAt || null;
  const activeUntil = user?.accountActiveUntil || null;
  const untilMs = activeUntil ? new Date(activeUntil).getTime() : 0;
  const remainingMs = Math.max(0, untilMs - now);
  const isActive = untilMs > now && user?.accountStatus !== 'SUSPENDED' && user?.accountStatus !== 'DEACTIVATED';
  return {
    status: user?.accountStatus || 'INACTIVE',
    isActive,
    nowMs: now,
    activatedAt,
    activatedAtLocal: activatedAt ? formatLocalISO(activatedAt) : null,
    activatedAtMs: activatedAt ? toEpochMs(activatedAt) : null,
    activeUntil,
    activeUntilLocal: activeUntil ? formatLocalISO(activeUntil) : null,
    activeUntilMs: activeUntil ? untilMs : null,
    remainingMs,
    remainingSeconds: Math.floor(remainingMs / 1000),
    remainingDays: activeUntil ? Math.ceil(remainingMs / (24 * 60 * 60 * 1000)) : 0,
  };
}

export async function requireActiveMembership(req, res, next) {
  try {
    const userId = req.user?.id || req.user?.sub;
    if (!userId) return res.status(401).json({ error: 'unauthorized' });

    const user = await User.findById(userId);
    if (!user) return res.status(401).json({ error: 'unauthorized' });

    // Auto-sync status based on expiry
    const before = user.accountStatus;
    const now = Date.now();
    const until = user.accountActiveUntil ? user.accountActiveUntil.getTime() : 0;
    if (user.accountStatus !== 'SUSPENDED' && user.accountStatus !== 'DEACTIVATED') {
      user.accountStatus = until > now ? 'ACTIVE' : 'INACTIVE';
    }
    if (user.accountStatus !== before) {
      try { await user.save(); } catch (_) {}
    }

    const membership = buildMembershipPayloadFromUser(user);
    req.membership = membership;
    if (!membership.isActive) {
      return res.status(402).json({ error: 'MEMBERSHIP_INACTIVE', topupRequired: true, membership });
    }
    return next();
  } catch (err) {
    return next(err);
  }
}

export function attachMembershipOptional() {
  return async (req, res, next) => {
    try {
      const userId = req.user?.id || req.user?.sub;
      if (userId) {
        const user = await User.findById(userId).lean();
        if (user) req.membership = buildMembershipPayloadFromUser(user);
      }
    } catch (_) {}
    return next();
  };
}

