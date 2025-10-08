import Wallet from '../models/Wallet.js';

/**
 * Ensure a wallet document exists for the given user.
 * Creates the wallet lazily if needed and returns the up-to-date document.
 */
export async function ensureWallet(userId, session) {
  const opts = {
    upsert: true,
    new: true,
    setDefaultsOnInsert: true,
  };
  if (session) {
    opts.session = session;
  }

  const wallet = await Wallet.findOneAndUpdate(
    { userId },
    { $setOnInsert: { balance: 0 } },
    opts,
  );

  return wallet;
}

