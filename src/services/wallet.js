import Wallet from '../models/Wallet.js';
import User from '../models/User.js';

/**
 * Ensure a wallet document exists for the given user.
 * Creates the wallet lazily if needed and returns the up-to-date document.
 */
export async function ensureWallet(userId, session) {
  const query = Wallet.findOne({ userId });
  if (session) {
    query.session(session);
  }
  const existing = await query.exec();
  if (existing) {
    return existing;
  }

  let initialBalancePaise = 0;
  try {
    const userQuery = User.findById(userId).select('walletBalance');
    if (session) {
      userQuery.session(session);
    }
    const user = await userQuery.lean().exec();
    if (user && Number.isFinite(user.walletBalance)) {
      initialBalancePaise = Math.max(0, Math.round(Number(user.walletBalance) * 100));
    }
  } catch (err) {
    console.warn('ensureWallet user lookup failed', err);
  }

  try {
    const [created] = await Wallet.create(
      [{ userId, balance: initialBalancePaise }],
      session ? { session } : undefined,
    );
    return created;
  } catch (err) {
    if (err?.code === 11000) {
      const retryQuery = Wallet.findOne({ userId });
      if (session) {
        retryQuery.session(session);
      }
      const retry = await retryQuery.exec();
      if (retry) return retry;
    }
    throw err;
  }
}
