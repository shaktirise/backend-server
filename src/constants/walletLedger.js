export const WALLET_LEDGER_TYPES = Object.freeze({
  DEPOSIT: 'DEPOSIT',
  BONUS_CREDIT: 'BONUS_CREDIT',
  BONUS_RELEASE: 'BONUS_RELEASE',
  WITHDRAWAL: 'WITHDRAWAL',
  BONUS_REVERSAL: 'BONUS_REVERSAL',
  PURCHASE: 'PURCHASE',
});

export const WALLET_LEDGER_LEGACY_TYPES = Object.freeze({
  TOPUP: 'TOPUP',
  REFERRAL: 'REFERRAL',
});

export const WALLET_LEDGER_ALLOWED_TYPES = Object.freeze([
  ...Object.values(WALLET_LEDGER_TYPES),
  ...Object.values(WALLET_LEDGER_LEGACY_TYPES),
]);

export const WALLET_LEDGER_CREDIT_TYPES = Object.freeze([
  WALLET_LEDGER_TYPES.DEPOSIT,
  WALLET_LEDGER_TYPES.BONUS_CREDIT,
  WALLET_LEDGER_TYPES.BONUS_RELEASE,
]);

export const WALLET_LEDGER_DEBIT_TYPES = Object.freeze([
  WALLET_LEDGER_TYPES.WITHDRAWAL,
  WALLET_LEDGER_TYPES.BONUS_REVERSAL,
  WALLET_LEDGER_TYPES.PURCHASE,
]);

export function normalizeLedgerType(rawType) {
  const value = String(rawType || '').toUpperCase();
  if (WALLET_LEDGER_ALLOWED_TYPES.includes(value)) {
    if (value === WALLET_LEDGER_LEGACY_TYPES.TOPUP) {
      return WALLET_LEDGER_TYPES.DEPOSIT;
    }
    if (value === WALLET_LEDGER_LEGACY_TYPES.REFERRAL) {
      return WALLET_LEDGER_TYPES.BONUS_CREDIT;
    }
    return value;
  }
  return null;
}

export function isCreditType(type) {
  const normalized = normalizeLedgerType(type);
  return normalized ? WALLET_LEDGER_CREDIT_TYPES.includes(normalized) : false;
}

export function isDebitType(type) {
  const normalized = normalizeLedgerType(type);
  return normalized ? WALLET_LEDGER_DEBIT_TYPES.includes(normalized) : false;
}
