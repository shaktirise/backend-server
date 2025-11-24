import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { auth, admin } from '../middleware/auth.js';
import User from '../models/User.js';
import Wallet from '../models/Wallet.js';
import WalletLedger from '../models/WalletLedger.js';
import ReferralLedger from '../models/ReferralLedger.js';
import ReferralWithdrawalRequest from '../models/ReferralWithdrawalRequest.js';
import Purchase from '../models/Purchase.js';
import DailyTip from '../models/DailyTip.js';
import BonusPayout from '../models/BonusPayout.js';
import ActivationEvent from '../models/ActivationEvent.js';
import ReferralClosure from '../models/ReferralClosure.js';
import {
  WALLET_LEDGER_CREDIT_TYPES,
  WALLET_LEDGER_DEBIT_TYPES,
  WALLET_LEDGER_TYPES,
  WALLET_LEDGER_LEGACY_TYPES,
  normalizeLedgerType,
} from '../constants/walletLedger.js';
import {
  parseDateRange,
  toObjectId,
  parsePagination,
  ensureNumber,
  ensureInt,
  toRupees,
} from '../utils/admin.js';
import { ensureReferralCode } from '../services/referral.js';

const router = express.Router();

router.use(auth, admin);

function buildUserPublicProfile(user) {
  if (!user) return null;
  return {
    id: user._id,
    name: user.name || null,
    email: user.email || null,
    phone: user.phone || null,
    role: user.role,
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt,
    referralCode: user.referralCode || null,
    referralCount: user.referralCount || 0,
    loginCount: user.loginCount || 0,
    isDemo: Boolean(user.isDemo),
  };
}

function buildWithdrawalPayload(doc) {
  if (!doc) return null;
  return {
    id: doc._id,
    user: buildUserPublicProfile(doc.userId),
    amountPaise: doc.amountPaise,
    amountRupees: toRupees(doc.amountPaise),
    method: doc.method || null,
    upiId: doc.upiId || null,
    bank: {
      accountName: doc.bankAccountName || null,
      accountNumber: doc.bankAccountNumber || null,
      ifsc: doc.bankIfsc || null,
      bankName: doc.bankName || null,
    },
    contactName: doc.contactName || null,
    contactMobile: doc.contactMobile || null,
    status: doc.status,
    note: doc.note || null,
    adminNote: doc.adminNote || null,
    paymentRef: doc.paymentRef || null,
    ledgerCount: Array.isArray(doc.ledgerEntryIds) ? doc.ledgerEntryIds.length : 0,
    processedAt: doc.processedAt || null,
    processedBy:
      doc.processedBy && typeof doc.processedBy === 'object' && doc.processedBy._id
        ? buildUserPublicProfile(doc.processedBy)
        : doc.processedBy
          ? doc.processedBy.toString()
          : null,
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
  };
}

const LEDGER_TYPE_FILTERS = {
  [WALLET_LEDGER_TYPES.DEPOSIT]: [
    WALLET_LEDGER_TYPES.DEPOSIT,
    WALLET_LEDGER_LEGACY_TYPES.TOPUP,
  ],
  [WALLET_LEDGER_TYPES.BONUS_CREDIT]: [
    WALLET_LEDGER_TYPES.BONUS_CREDIT,
    WALLET_LEDGER_LEGACY_TYPES.REFERRAL,
  ],
};

function expandLedgerTypes(types) {
  const result = new Set();
  types.forEach((type) => {
    if (!type) return;
    result.add(type);
    const extras = LEDGER_TYPE_FILTERS[type];
    if (extras) {
      extras.forEach((extra) => result.add(extra));
    }
  });
  return Array.from(result);
}

function parseDate(value) {
  if (!value) return null;
  const ts = Date.parse(value);
  if (Number.isNaN(ts)) return null;
  return new Date(ts);
}

async function computeReferralCountsFallback(userId, depth) {
  const maxDepth = Number.isFinite(depth) && depth > 0 ? depth : 10;
  let currentIds = [userId];
  const counts = [];
  const visited = new Set(currentIds.map((id) => id.toString()));

  for (let level = 1; level <= maxDepth; level += 1) {
    const docs = await User.find({ referredBy: { $in: currentIds } })
      .select('_id')
      .lean();
    const nextIds = docs
      .map((doc) => doc._id)
      .filter((id) => !visited.has(id.toString()));

    counts.push({ level, count: nextIds.length });
    nextIds.forEach((id) => visited.add(id.toString()));
    if (!nextIds.length) {
      for (let remaining = level + 1; remaining <= maxDepth; remaining += 1) {
        counts.push({ level: remaining, count: 0 });
      }
      break;
    }
    currentIds = nextIds;
  }

  return counts;
}

async function loadReferralCounts(userId, depth) {
  const maxDepth = Number.isFinite(depth) && depth > 0 ? Math.min(depth, 10) : 10;
  const closureAgg = await ReferralClosure.aggregate([
    {
      $match: { ancestorId: userId, depth: { $gte: 1, $lte: maxDepth } },
    },
    {
      $group: { _id: '$depth', count: { $sum: 1 } },
    },
  ]);

  if (!closureAgg.length) {
    return computeReferralCountsFallback(userId, maxDepth);
  }

  const countsMap = new Map(closureAgg.map((row) => [row._id, row.count]));
  const counts = [];
  for (let level = 1; level <= maxDepth; level += 1) {
    counts.push({ level, count: countsMap.get(level) || 0 });
  }
  return counts;
}

async function loadReferralTreeNodes(userId, depth) {
  const maxDepth = Number.isFinite(depth) && depth > 0 ? Math.min(depth, 10) : 10;
  const levelMap = new Map();

  const closureDocs = await ReferralClosure.find({
    ancestorId: userId,
    depth: { $gte: 1, $lte: maxDepth },
  })
    .select('descendantId depth')
    .lean();

  if (closureDocs.length) {
    closureDocs.forEach((doc) => {
      const list = levelMap.get(doc.depth) || [];
      list.push(doc.descendantId);
      levelMap.set(doc.depth, list);
    });
    return { levels: levelMap, usedClosure: true };
  }

  let current = [userId];
  for (let level = 1; level <= maxDepth; level += 1) {
    const children = await User.find({ referredBy: { $in: current } })
      .select('_id')
      .lean();
    const ids = children.map((doc) => doc._id);
    levelMap.set(level, ids);
    if (!ids.length) break;
    current = ids;
  }
  return { levels: levelMap, usedClosure: false };
}

router.get('/dashboard/overview', async (req, res) => {
  try {
    const { from, to } = parseDateRange(req.query);
    const userId = toObjectId(req.query.userId);

    const buildDateQuery = (field) => {
      if (!from && !to) return {};
      const range = {};
      if (from) range.$gte = from;
      if (to) range.$lte = to;
      return Object.keys(range).length ? { [field]: range } : {};
    };

    const baseUserFilter = userId ? { _id: userId } : {};

    const ledgerMatch = {
      ...(userId ? { userId } : {}),
      ...buildDateQuery('createdAt'),
    };

    const effectiveRange = {};
    if (from) effectiveRange.$gte = from;
    if (to) effectiveRange.$lte = to;

    const bonusPipeline = [
      ...(userId ? [{ $match: { uplineUserId: userId } }] : []),
      {
        $addFields: {
          effectiveAt: {
            $cond: [
              {
                $and: [
                  { $in: ['$status', ['RELEASED', 'REVERSED']] },
                  { $ifNull: ['$processedAt', false] },
                ],
              },
              '$processedAt',
              '$createdAt',
            ],
          },
        },
      },
      ...(Object.keys(effectiveRange).length
        ? [
            {
              $match: {
                effectiveAt: effectiveRange,
              },
            },
          ]
        : []),
      {
        $group: {
          _id: '$status',
          amountPaise: { $sum: '$amountPaise' },
          count: { $sum: 1 },
        },
      },
    ];

    const [
      totalUsers,
      activeUsers,
      kycVerifiedUsers,
      newSignups,
      ledgerAggRaw,
      bonusAggRaw,
    ] = await Promise.all([
      User.countDocuments(baseUserFilter),
      User.countDocuments({
        ...baseUserFilter,
        ...buildDateQuery('lastLoginAt'),
      }),
      User.countDocuments({
        ...baseUserFilter,
        kycStatus: 'VERIFIED',
        ...buildDateQuery('kycVerifiedAt'),
      }),
      User.countDocuments({
        ...baseUserFilter,
        ...buildDateQuery('createdAt'),
      }),
      WalletLedger.aggregate([
        {
          $match: ledgerMatch,
        },
        {
          $group: {
            _id: '$type',
            totalAmount: { $sum: '$amount' },
            totalAbsolute: { $sum: { $abs: '$amount' } },
            count: { $sum: 1 },
          },
        },
      ]),
      BonusPayout.aggregate(bonusPipeline),
    ]);

    const ledgerByType = {};
    let totalCreditPaise = 0;
    let totalDebitPaise = 0;
    let netInflowPaise = 0;

    ledgerAggRaw.forEach((row) => {
      const normalized = normalizeLedgerType(row._id);
      if (!normalized) return;
      const totalAmount = ensureNumber(row.totalAmount);
      const totalAbsolute = ensureNumber(row.totalAbsolute);
      const count = ensureInt(row.count);

      if (!ledgerByType[normalized]) {
        ledgerByType[normalized] = { amountPaise: 0, absolutePaise: 0, count: 0 };
      }

      ledgerByType[normalized].amountPaise += totalAmount;
      ledgerByType[normalized].absolutePaise += totalAbsolute;
      ledgerByType[normalized].count += count;

      if (WALLET_LEDGER_CREDIT_TYPES.includes(normalized)) {
        totalCreditPaise += totalAmount;
      } else if (WALLET_LEDGER_DEBIT_TYPES.includes(normalized)) {
        totalDebitPaise += totalAbsolute;
      }

      netInflowPaise += totalAmount;
    });

    const depositsRaw = ledgerByType[WALLET_LEDGER_TYPES.DEPOSIT] || {
      amountPaise: 0,
      absolutePaise: 0,
      count: 0,
    };
    const withdrawalsRaw = ledgerByType[WALLET_LEDGER_TYPES.WITHDRAWAL] || {
      amountPaise: 0,
      absolutePaise: 0,
      count: 0,
    };

    const deposits = {
      count: ensureInt(depositsRaw.count),
      amountPaise: Math.max(0, ensureNumber(depositsRaw.amountPaise)),
    };
    deposits.amountRupees = toRupees(deposits.amountPaise);

    const withdrawals = {
      count: ensureInt(withdrawalsRaw.count),
      amountPaise: Math.abs(ensureNumber(withdrawalsRaw.amountPaise)),
    };
    withdrawals.amountRupees = toRupees(withdrawals.amountPaise);

    const ledgerResponse = Object.fromEntries(
      Object.entries(ledgerByType).map(([type, info]) => [
        type,
        {
          count: ensureInt(info.count),
          netPaise: ensureNumber(info.amountPaise),
          netRupees: toRupees(info.amountPaise),
          absolutePaise: ensureNumber(info.absolutePaise),
          absoluteRupees: toRupees(info.absolutePaise),
        },
      ]),
    );

    const commissionSummary = {
      pending: { count: 0, amountPaise: 0 },
      released: { count: 0, amountPaise: 0 },
      reversed: { count: 0, amountPaise: 0 },
    };

    bonusAggRaw.forEach((row) => {
      const status = typeof row._id === 'string' ? row._id.toUpperCase() : null;
      if (!status) return;
      if (status === 'PENDING') {
        commissionSummary.pending.count += ensureInt(row.count);
        commissionSummary.pending.amountPaise += ensureNumber(row.amountPaise);
      } else if (status === 'RELEASED') {
        commissionSummary.released.count += ensureInt(row.count);
        commissionSummary.released.amountPaise += ensureNumber(row.amountPaise);
      } else if (status === 'REVERSED') {
        commissionSummary.reversed.count += ensureInt(row.count);
        commissionSummary.reversed.amountPaise += ensureNumber(row.amountPaise);
      }
    });

    Object.values(commissionSummary).forEach((summary) => {
      summary.amountPaise = ensureNumber(summary.amountPaise);
      summary.amountRupees = toRupees(summary.amountPaise);
      summary.count = ensureInt(summary.count);
    });

    const commissionNetPaise =
      commissionSummary.released.amountPaise - commissionSummary.reversed.amountPaise;

    const moneySummary = {
      deposits,
      withdrawals,
      commissions: {
        pending: commissionSummary.pending,
        released: commissionSummary.released,
        reversed: commissionSummary.reversed,
        netPaise: commissionNetPaise,
        netRupees: toRupees(commissionNetPaise),
      },
      credits: {
        amountPaise: Math.max(0, totalCreditPaise),
        amountRupees: toRupees(Math.max(0, totalCreditPaise)),
      },
      debits: {
        amountPaise: Math.max(0, totalDebitPaise),
        amountRupees: toRupees(Math.max(0, totalDebitPaise)),
      },
      netInflowPaise: netInflowPaise,
      netInflowRupees: toRupees(netInflowPaise),
    };

    return res.json({
      timeframe: {
        from: from ? from.toISOString() : null,
        to: to ? to.toISOString() : null,
      },
      filters: {
        userId: userId ? userId.toString() : null,
      },
      totals: {
        users: ensureInt(totalUsers),
        activeUsers: ensureInt(activeUsers),
        kycVerifiedUsers: ensureInt(kycVerifiedUsers),
        newSignups: ensureInt(newSignups),
      },
      money: moneySummary,
      ledger: {
        byType: ledgerResponse,
      },
    });
  } catch (err) {
    console.error('admin overview error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/dashboard/calls', async (req, res) => {
  try {
    const { limit, skip, page } = parsePagination(req.query);
    const query = {};
    const userId = toObjectId(req.query.userId);
    if (userId) {
      query.user = userId;
    }

    const startDate = parseDate(req.query.start);
    const endDate = parseDate(req.query.end);
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = startDate;
      if (endDate) query.createdAt.$lte = endDate;
    }

    const [itemsRaw, total] = await Promise.all([
      Purchase.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate('user', 'name email phone')
        .populate('advice', 'category price createdAt text')
        .lean(),
      Purchase.countDocuments(query),
    ]);

    const items = itemsRaw.map((purchase) => {
      const amountPaise = Number.isFinite(purchase.amountPaise)
        ? purchase.amountPaise
        : Number.isFinite(purchase.amount)
          ? Math.round(purchase.amount * 100)
          : 0;
      return {
        id: purchase._id,
        createdAt: purchase.createdAt,
        amountPaise,
        amountRupees: toRupees(amountPaise),
        note: purchase.note || null,
        category: purchase.category || purchase.advice?.category || null,
        title: purchase.title || purchase.advice?.text || null,
        user: buildUserPublicProfile(purchase.user),
        adviceId: purchase.advice?._id || purchase.advice || null,
        walletLedgerId: purchase.walletLedgerId || null,
      };
    });

    return res.json({
      page,
      limit,
      total,
      items,
    });
  } catch (err) {
    console.error('admin calls list error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/wallet-ledger', async (req, res) => {
  try {
    const { page, pageSize, limit, skip } = parsePagination(req.query);
    const { from, to } = parseDateRange(req.query);
    const userId = toObjectId(req.query.userId);

    const match = {};
    if (userId) {
      match.userId = userId;
    }
    if (from || to) {
      match.createdAt = {};
      if (from) match.createdAt.$gte = from;
      if (to) match.createdAt.$lte = to;
    }

    const rawTypeParam = req.query.type ?? req.query.types;
    let normalizedTypes = [];
    if (rawTypeParam) {
      normalizedTypes = String(rawTypeParam)
        .split(',')
        .map((part) => normalizeLedgerType(part.trim().toUpperCase()))
        .filter(Boolean);
      if (normalizedTypes.length) {
        const expanded = expandLedgerTypes(normalizedTypes);
        match.$or = [
          { type: { $in: expanded } },
          { normalizedType: { $in: expanded } },
        ];
      }
    }

    const [entries, total, summaryAgg] = await Promise.all([
      WalletLedger.find(match)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate('userId', 'name email phone role referralCode createdAt lastLoginAt')
        .populate('walletId', '_id userId')
        .lean(),
      WalletLedger.countDocuments(match),
      WalletLedger.aggregate([
        { $match: match },
        {
          $group: {
            _id: '$type',
            totalAmount: { $sum: '$amount' },
            totalAbsolute: { $sum: { $abs: '$amount' } },
            count: { $sum: 1 },
          },
        },
      ]),
    ]);

    let totalCreditPaise = 0;
    let totalDebitPaise = 0;
    let netPaise = 0;
    const summaryByType = {};

    summaryAgg.forEach((row) => {
      const normalized = normalizeLedgerType(row._id);
      if (!normalized) return;
      const totalAmount = ensureNumber(row.totalAmount);
      const totalAbsolute = ensureNumber(row.totalAbsolute);
      const count = ensureInt(row.count);
      summaryByType[normalized] = {
        count,
        netPaise: totalAmount,
        netRupees: toRupees(totalAmount),
        absolutePaise: totalAbsolute,
        absoluteRupees: toRupees(totalAbsolute),
      };
      if (WALLET_LEDGER_CREDIT_TYPES.includes(normalized)) {
        totalCreditPaise += totalAmount;
      } else if (WALLET_LEDGER_DEBIT_TYPES.includes(normalized)) {
        totalDebitPaise += totalAbsolute;
      }
      netPaise += totalAmount;
    });

    const items = entries.map((entry) => {
      const normalized = normalizeLedgerType(entry.normalizedType || entry.type);
      const amountPaise = ensureNumber(entry.amount);
      const isCredit = normalized
        ? WALLET_LEDGER_CREDIT_TYPES.includes(normalized)
        : amountPaise >= 0;
      return {
        id: entry._id,
        type: normalized || entry.type,
        rawType: entry.type,
        amountPaise,
        amountRupees: toRupees(amountPaise),
        direction: isCredit ? 'CREDIT' : 'DEBIT',
        note: entry.note || null,
        extRef: entry.extRef || null,
        metadata: entry.metadata || null,
        createdAt: entry.createdAt,
        user: buildUserPublicProfile(entry.userId),
      };
    });

    return res.json({
      page,
      pageSize: pageSize || limit,
      limit,
      total,
      timeframe: {
        from: from ? from.toISOString() : null,
        to: to ? to.toISOString() : null,
      },
      summary: {
        creditsPaise: Math.max(0, totalCreditPaise),
        creditsRupees: toRupees(Math.max(0, totalCreditPaise)),
        debitsPaise: Math.max(0, totalDebitPaise),
        debitsRupees: toRupees(Math.max(0, totalDebitPaise)),
        netPaise,
        netRupees: toRupees(netPaise),
        byType: summaryByType,
      },
      items,
    });
  } catch (err) {
    console.error('admin wallet ledger error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/users/:userId/summary', async (req, res) => {
  try {
    const userId = toObjectId(req.params.userId);
    if (!userId) return res.status(400).json({ error: 'invalid_user_id' });

    const { from, to } = parseDateRange(req.query);
    const depthRaw = Number.parseInt(req.query.depth ?? req.query.levelDepth ?? '10', 10);
    const depth = Number.isFinite(depthRaw) && depthRaw > 0 ? Math.min(depthRaw, 10) : 10;

    const user = await User.findById(userId).lean();
    if (!user) return res.status(404).json({ error: 'user_not_found' });

    const ledgerMatch = {
      userId,
    };
    if (from || to) {
      ledgerMatch.createdAt = {};
      if (from) ledgerMatch.createdAt.$gte = from;
      if (to) ledgerMatch.createdAt.$lte = to;
    }

    const bonusMatchBase = {
      uplineUserId: userId,
    };
    const bonusEffectiveRange = {};
    if (from) bonusEffectiveRange.$gte = from;
    if (to) bonusEffectiveRange.$lte = to;

    const activationMatch = {
      userId,
      status: 'SUCCEEDED',
    };
    if (from || to) {
      activationMatch.occurredAt = {};
      if (from) activationMatch.occurredAt.$gte = from;
      if (to) activationMatch.occurredAt.$lte = to;
    }

    const [
      wallet,
      ledgerAgg,
      bonusAgg,
      activationAgg,
      referralCounts,
    ] = await Promise.all([
      Wallet.findOne({ userId }).lean(),
      WalletLedger.aggregate([
        { $match: ledgerMatch },
        {
          $group: {
            _id: '$type',
            totalAmount: { $sum: '$amount' },
            totalAbsolute: { $sum: { $abs: '$amount' } },
            count: { $sum: 1 },
          },
        },
      ]),
      BonusPayout.aggregate([
        { $match: bonusMatchBase },
        {
          $addFields: {
            effectiveAt: {
              $cond: [
                {
                  $and: [
                    { $in: ['$status', ['RELEASED', 'REVERSED']] },
                    { $ifNull: ['$processedAt', false] },
                  ],
                },
                '$processedAt',
                '$createdAt',
              ],
            },
          },
        },
        ...(Object.keys(bonusEffectiveRange).length
          ? [
              {
                $match: {
                  effectiveAt: bonusEffectiveRange,
                },
              },
            ]
          : []),
        {
          $group: {
            _id: { level: '$level', status: '$status' },
            amountPaise: { $sum: '$amountPaise' },
            count: { $sum: 1 },
          },
        },
      ]),
      ActivationEvent.aggregate([
        { $match: activationMatch },
        {
          $group: {
            _id: null,
            amountPaise: { $sum: '$amountPaise' },
            count: { $sum: 1 },
          },
        },
      ]),
      loadReferralCounts(userId, depth),
    ]);

    const ledgerSummary = {
      byType: {},
      creditsPaise: 0,
      debitsPaise: 0,
      netPaise: 0,
    };

    ledgerAgg.forEach((row) => {
      const normalized = normalizeLedgerType(row._id);
      if (!normalized) return;
      const totalAmount = ensureNumber(row.totalAmount);
      const totalAbsolute = ensureNumber(row.totalAbsolute);
      const count = ensureInt(row.count);
      ledgerSummary.byType[normalized] = {
        count,
        netPaise: totalAmount,
        netRupees: toRupees(totalAmount),
        absolutePaise: totalAbsolute,
        absoluteRupees: toRupees(totalAbsolute),
      };
      if (WALLET_LEDGER_CREDIT_TYPES.includes(normalized)) {
        ledgerSummary.creditsPaise += totalAmount;
      } else if (WALLET_LEDGER_DEBIT_TYPES.includes(normalized)) {
        ledgerSummary.debitsPaise += totalAbsolute;
      }
      ledgerSummary.netPaise += totalAmount;
    });

    const deposits = ledgerSummary.byType[WALLET_LEDGER_TYPES.DEPOSIT] || {
      count: 0,
      netPaise: 0,
    };

    const activationSummaryRaw = activationAgg[0] || { amountPaise: 0, count: 0 };
    const activationSummary = {
      count: ensureInt(activationSummaryRaw.count),
      amountPaise: ensureNumber(activationSummaryRaw.amountPaise),
    };
    activationSummary.amountRupees = toRupees(activationSummary.amountPaise);

    const commissionByLevel = {};
    let pendingCommissionPaise = 0;
    let releasedCommissionPaise = 0;

    bonusAgg.forEach((row) => {
      const level = ensureInt(row._id?.level);
      const status = typeof row._id?.status === 'string' ? row._id.status.toUpperCase() : null;
      if (!level || !status) return;
      if (!commissionByLevel[level]) {
        commissionByLevel[level] = {
          pending: { amountPaise: 0, count: 0 },
          released: { amountPaise: 0, count: 0 },
          reversed: { amountPaise: 0, count: 0 },
        };
      }
      const bucket = commissionByLevel[level];
      const amountPaise = ensureNumber(row.amountPaise);
      const count = ensureInt(row.count);
      if (status === 'PENDING') {
        bucket.pending.amountPaise += amountPaise;
        bucket.pending.count += count;
        pendingCommissionPaise += amountPaise;
      } else if (status === 'RELEASED') {
        bucket.released.amountPaise += amountPaise;
        bucket.released.count += count;
        releasedCommissionPaise += amountPaise;
      } else if (status === 'REVERSED') {
        bucket.reversed.amountPaise += amountPaise;
        bucket.reversed.count += count;
        releasedCommissionPaise -= amountPaise;
      }
    });

    const commissionLevels = [];
    for (let level = 1; level <= depth; level += 1) {
      const bucket =
        commissionByLevel[level] || {
          pending: { amountPaise: 0, count: 0 },
          released: { amountPaise: 0, count: 0 },
          reversed: { amountPaise: 0, count: 0 },
        };
      Object.values(bucket).forEach((entry) => {
        entry.amountPaise = ensureNumber(entry.amountPaise);
        entry.amountRupees = toRupees(entry.amountPaise);
        entry.count = ensureInt(entry.count);
      });
      commissionLevels.push({
        level,
        ...bucket,
      });
    }

    const walletBalancePaise = ensureNumber(wallet?.balance);
    const response = {
      timeframe: {
        from: from ? from.toISOString() : null,
        to: to ? to.toISOString() : null,
      },
      user: buildUserPublicProfile(user),
      wallet: {
        availablePaise: walletBalancePaise,
        availableRupees: toRupees(walletBalancePaise),
        pendingCommissionPaise,
        pendingCommissionRupees: toRupees(pendingCommissionPaise),
        releasedCommissionPaise,
        releasedCommissionRupees: toRupees(releasedCommissionPaise),
      },
      ledger: {
        creditsPaise: ledgerSummary.creditsPaise,
        creditsRupees: toRupees(ledgerSummary.creditsPaise),
        debitsPaise: ledgerSummary.debitsPaise,
        debitsRupees: toRupees(ledgerSummary.debitsPaise),
        netPaise: ledgerSummary.netPaise,
        netRupees: toRupees(ledgerSummary.netPaise),
        byType: ledgerSummary.byType,
      },
      topups: {
        count: ensureInt(deposits.count),
        amountPaise: Math.max(0, ensureNumber(deposits.netPaise)),
        amountRupees: toRupees(Math.max(0, ensureNumber(deposits.netPaise))),
      },
      activationEvents: activationSummary,
      referrals: {
        depth,
        counts: referralCounts,
      },
      commissionsByLevel: commissionLevels,
    };

    return res.json(response);
  } catch (err) {
    console.error('admin user summary error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/users/:userId/referral-tree', async (req, res) => {
  try {
    const userId = toObjectId(req.params.userId);
    if (!userId) return res.status(400).json({ error: 'invalid_user_id' });

    const { from, to } = parseDateRange(req.query);
    const depthRaw = Number.parseInt(req.query.depth ?? req.query.levelDepth ?? '10', 10);
    const depth = Number.isFinite(depthRaw) && depthRaw > 0 ? Math.min(depthRaw, 10) : 10;

    const { levels, usedClosure } = await loadReferralTreeNodes(userId, depth);

    const descendantIdSet = new Map();
    levels.forEach((ids) => {
      ids.forEach((id) => {
        if (id) descendantIdSet.set(id.toString(), id);
      });
    });
    const descendantIds = Array.from(descendantIdSet.values());

    const [descendantUsers, bonusAgg] = await Promise.all([
      descendantIds.length
        ? User.find({ _id: { $in: descendantIds } })
            .select('name email phone role createdAt lastLoginAt referralCode referralCount')
            .lean()
        : [],
      descendantIds.length
        ? BonusPayout.aggregate([
            {
              $match: {
                uplineUserId: userId,
                downlineUserId: { $in: descendantIds },
              },
            },
            {
              $addFields: {
                effectiveAt: {
                  $cond: [
                    {
                      $and: [
                        { $in: ['$status', ['RELEASED', 'REVERSED']] },
                        { $ifNull: ['$processedAt', false] },
                      ],
                    },
                    '$processedAt',
                    '$createdAt',
                  ],
                },
              },
            },
            ...(from || to
              ? [
                  {
                    $match: {
                      effectiveAt: {
                        ...(from ? { $gte: from } : {}),
                        ...(to ? { $lte: to } : {}),
                      },
                    },
                  },
                ]
              : []),
            {
              $group: {
                _id: {
                  downline: '$downlineUserId',
                  status: '$status',
                  level: '$level',
                },
                amountPaise: { $sum: '$amountPaise' },
                count: { $sum: 1 },
              },
            },
          ])
        : [],
    ]);

    const userMap = new Map(
      descendantUsers.map((doc) => [doc._id.toString(), doc]),
    );

    const earningsByDownline = new Map();
    bonusAgg.forEach((row) => {
      const downlineId = row._id?.downline?.toString();
      const status = typeof row._id?.status === 'string' ? row._id.status.toUpperCase() : null;
      const level = ensureInt(row._id?.level);
      if (!downlineId || !status || !level) return;
      if (!earningsByDownline.has(downlineId)) {
        earningsByDownline.set(downlineId, {
          pending: { amountPaise: 0, count: 0 },
          released: { amountPaise: 0, count: 0 },
          reversed: { amountPaise: 0, count: 0 },
          level,
        });
      }
      const record = earningsByDownline.get(downlineId);
      const amountPaise = ensureNumber(row.amountPaise);
      const count = ensureInt(row.count);
      if (status === 'PENDING') {
        record.pending.amountPaise += amountPaise;
        record.pending.count += count;
      } else if (status === 'RELEASED') {
        record.released.amountPaise += amountPaise;
        record.released.count += count;
      } else if (status === 'REVERSED') {
        record.reversed.amountPaise += amountPaise;
        record.reversed.count += count;
      }
    });

    const levelsResponse = [];
    for (let lvl = 1; lvl <= depth; lvl += 1) {
      const ids = levels.get(lvl) || [];
      const descendants = ids.map((id) => {
        const key = id.toString();
        const user = userMap.get(key);
        const earnings = earningsByDownline.get(key) || {
          pending: { amountPaise: 0, count: 0 },
          released: { amountPaise: 0, count: 0 },
          reversed: { amountPaise: 0, count: 0 },
        };
        const normalizeEarnings = (entry) => ({
          amountPaise: ensureNumber(entry.amountPaise),
          amountRupees: toRupees(entry.amountPaise),
          count: ensureInt(entry.count),
        });
        return {
          id,
          user: buildUserPublicProfile(user),
          earnings: {
            pending: normalizeEarnings(earnings.pending || {}),
            released: normalizeEarnings(earnings.released || {}),
            reversed: normalizeEarnings(earnings.reversed || {}),
          },
        };
      });
      levelsResponse.push({
        level: lvl,
        descendantCount: descendants.length,
        descendants,
      });
    }

    const includeFlat =
      String(req.query.flat || '') === '1'
      || String(req.query.flat || '').toLowerCase() === 'true';
    const includeEmailsOnly =
      String(req.query.emailsOnly || '') === '1'
      || String(req.query.emailsOnly || '').toLowerCase() === 'true';

    const responsePayload = {
      timeframe: {
        from: from ? from.toISOString() : null,
        to: to ? to.toISOString() : null,
      },
      depth,
      usedClosure,
      levels: levelsResponse,
    };

    if (includeFlat) {
      const flat = [];
      levelsResponse.forEach((lvl) => {
        lvl.descendants.forEach((d) => {
          flat.push({ level: lvl.level, id: d.id, user: d.user, earnings: d.earnings });
        });
      });
      responsePayload.flat = flat;
    }

    if (includeEmailsOnly) {
      const emails = [];
      levelsResponse.forEach((lvl) => {
        lvl.descendants.forEach((d) => {
          if (d?.user?.email) emails.push(d.user.email);
        });
      });
      responsePayload.emails = emails;
    }

    return res.json(responsePayload);
  } catch (err) {
    console.error('admin referral tree error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/commissions/summary', async (req, res) => {
  try {
    const { from, to } = parseDateRange(req.query);
    const userId = toObjectId(req.query.userId);
    const downlineId = toObjectId(req.query.downlineId);
    const depthRaw = Number.parseInt(req.query.depth ?? req.query.levelDepth ?? '10', 10);
    const depth = Number.isFinite(depthRaw) && depthRaw > 0 ? Math.min(depthRaw, 50) : null;

    const match = {};
    if (userId) match.uplineUserId = userId;
    if (downlineId) match.downlineUserId = downlineId;
    if (depth) match.level = { $lte: depth };

    const effectiveRange = {};
    if (from) effectiveRange.$gte = from;
    if (to) effectiveRange.$lte = to;

    const bonusAgg = await BonusPayout.aggregate([
      { $match: match },
      {
        $addFields: {
          effectiveAt: {
            $cond: [
              {
                $and: [
                  { $in: ['$status', ['RELEASED', 'REVERSED']] },
                  { $ifNull: ['$processedAt', false] },
                ],
              },
              '$processedAt',
              '$createdAt',
            ],
          },
        },
      },
      ...(Object.keys(effectiveRange).length
        ? [
            {
              $match: {
                effectiveAt: effectiveRange,
              },
            },
          ]
        : []),
      {
        $group: {
          _id: { status: '$status', level: '$level' },
          amountPaise: { $sum: '$amountPaise' },
          count: { $sum: 1 },
        },
      },
    ]);

    const totals = {
      pending: { amountPaise: 0, count: 0 },
      released: { amountPaise: 0, count: 0 },
      reversed: { amountPaise: 0, count: 0 },
    };
    const byLevel = new Map();

    bonusAgg.forEach((row) => {
      const status = typeof row._id?.status === 'string' ? row._id.status.toUpperCase() : null;
      const level = ensureInt(row._id?.level);
      if (!status || !level) return;

      const amountPaise = ensureNumber(row.amountPaise);
      const count = ensureInt(row.count);

      if (!byLevel.has(level)) {
        byLevel.set(level, {
          pending: { amountPaise: 0, count: 0 },
          released: { amountPaise: 0, count: 0 },
          reversed: { amountPaise: 0, count: 0 },
        });
      }
      const bucket = byLevel.get(level);

      if (status === 'PENDING') {
        totals.pending.amountPaise += amountPaise;
        totals.pending.count += count;
        bucket.pending.amountPaise += amountPaise;
        bucket.pending.count += count;
      } else if (status === 'RELEASED') {
        totals.released.amountPaise += amountPaise;
        totals.released.count += count;
        bucket.released.amountPaise += amountPaise;
        bucket.released.count += count;
      } else if (status === 'REVERSED') {
        totals.reversed.amountPaise += amountPaise;
        totals.reversed.count += count;
        bucket.reversed.amountPaise += amountPaise;
        bucket.reversed.count += count;
      }
    });

    const levelSummaries = Array.from(byLevel.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([level, data]) => {
        Object.values(data).forEach((entry) => {
          entry.amountPaise = ensureNumber(entry.amountPaise);
          entry.amountRupees = toRupees(entry.amountPaise);
          entry.count = ensureInt(entry.count);
        });
        return {
          level,
          ...data,
        };
      });

    Object.values(totals).forEach((entry) => {
      entry.amountPaise = ensureNumber(entry.amountPaise);
      entry.amountRupees = toRupees(entry.amountPaise);
      entry.count = ensureInt(entry.count);
    });

    const netPaise = totals.released.amountPaise - totals.reversed.amountPaise;

    return res.json({
      timeframe: {
        from: from ? from.toISOString() : null,
        to: to ? to.toISOString() : null,
      },
      filters: {
        userId: userId ? userId.toString() : null,
        downlineId: downlineId ? downlineId.toString() : null,
        depth,
      },
      totals: {
        ...totals,
        netPaise,
        netRupees: toRupees(netPaise),
      },
      byLevel: levelSummaries,
    });
  } catch (err) {
    console.error('admin commissions summary error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/commissions', async (req, res) => {
  try {
    const { page, pageSize, limit, skip } = parsePagination(req.query);
    const { from, to } = parseDateRange(req.query);
    const userId = toObjectId(req.query.userId);
    const downlineId = toObjectId(req.query.downlineId);

    const statusParam = req.query.status ?? req.query.statuses;
    const statusList = statusParam
      ? String(statusParam)
          .split(',')
          .map((part) => part.trim().toUpperCase())
          .filter((value) => ['PENDING', 'RELEASED', 'REVERSED'].includes(value))
      : [];

    const levelParam = req.query.level ?? req.query.levels;
    const levelList = levelParam
      ? String(levelParam)
          .split(',')
          .map((part) => Number.parseInt(part.trim(), 10))
          .filter((num) => Number.isFinite(num) && num > 0)
      : [];

    const match = {};
    if (userId) match.uplineUserId = userId;
    if (downlineId) match.downlineUserId = downlineId;
    if (statusList.length) match.status = { $in: statusList };
    if (levelList.length) match.level = { $in: levelList };

    const effectiveRange = {};
    if (from) effectiveRange.$gte = from;
    if (to) effectiveRange.$lte = to;

    const pipeline = [
      { $match: match },
      {
        $addFields: {
          effectiveAt: {
            $cond: [
              {
                $and: [
                  { $in: ['$status', ['RELEASED', 'REVERSED']] },
                  { $ifNull: ['$processedAt', false] },
                ],
              },
              '$processedAt',
              '$createdAt',
            ],
          },
        },
      },
      ...(Object.keys(effectiveRange).length
        ? [
            {
              $match: {
                effectiveAt: effectiveRange,
              },
            },
          ]
        : []),
      {
        $sort: { effectiveAt: -1, createdAt: -1 },
      },
      {
        $facet: {
          items: [
            { $skip: skip },
            { $limit: limit },
            {
              $lookup: {
                from: 'users',
                localField: 'uplineUserId',
                foreignField: '_id',
                as: 'uplineUser',
                pipeline: [
                  {
                    $project: {
                      name: 1,
                      email: 1,
                      phone: 1,
                      role: 1,
                      referralCode: 1,
                      createdAt: 1,
                      lastLoginAt: 1,
                    },
                  },
                ],
              },
            },
            { $unwind: { path: '$uplineUser', preserveNullAndEmptyArrays: true } },
            {
              $lookup: {
                from: 'users',
                localField: 'downlineUserId',
                foreignField: '_id',
                as: 'downlineUser',
                pipeline: [
                  {
                    $project: {
                      name: 1,
                      email: 1,
                      phone: 1,
                      role: 1,
                      referralCode: 1,
                      createdAt: 1,
                      lastLoginAt: 1,
                    },
                  },
                ],
              },
            },
            { $unwind: { path: '$downlineUser', preserveNullAndEmptyArrays: true } },
          ],
          total: [{ $count: 'count' }],
        },
      },
      {
        $addFields: {
          total: { $ifNull: [{ $arrayElemAt: ['$total.count', 0] }, 0] },
        },
      },
      {
        $project: {
          total: 1,
          items: 1,
        },
      },
    ];

    const aggregated = await BonusPayout.aggregate(pipeline);
    const first = aggregated[0] || { items: [], total: 0 };

    const items = first.items.map((entry) => ({
      id: entry._id,
      level: entry.level,
      status: entry.status,
      amountPaise: ensureNumber(entry.amountPaise),
      amountRupees: toRupees(entry.amountPaise),
      createdAt: entry.createdAt,
      processedAt: entry.processedAt || null,
      note: entry.note || null,
      metadata: entry.metadata || null,
      uplineUser: buildUserPublicProfile(entry.uplineUser),
      downlineUser: buildUserPublicProfile(entry.downlineUser),
      activationEventId: entry.activationEventId || null,
      walletLedgerId: entry.walletLedgerId || null,
      reversalLedgerId: entry.reversalLedgerId || null,
      effectiveAt: entry.effectiveAt,
    }));

    return res.json({
      page,
      pageSize: pageSize || limit,
      limit,
      total: ensureInt(first.total),
      timeframe: {
        from: from ? from.toISOString() : null,
        to: to ? to.toISOString() : null,
      },
      filters: {
        userId: userId ? userId.toString() : null,
        downlineId: downlineId ? downlineId.toString() : null,
        statuses: statusList,
        levels: levelList,
      },
      items,
    });
  } catch (err) {
    console.error('admin commissions list error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/referrals/pending', async (req, res) => {
  try {
    const { limit, skip, page } = parsePagination(req.query);
    const query = { status: 'pending' };
    const userId = toObjectId(req.query.userId);
    if (userId) {
      query.userId = userId;
    }

    const [entries, total] = await Promise.all([
      ReferralLedger.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate('userId', 'name email phone')
        .populate('sourceUserId', 'name email phone')
        .lean(),
      ReferralLedger.countDocuments(query),
    ]);

    const items = entries.map((entry) => ({
      id: entry._id,
      level: entry.level,
      amountPaise: entry.amountPaise,
      amountRupees: toRupees(entry.amountPaise),
      status: entry.status,
      note: entry.note || null,
      createdAt: entry.createdAt,
      user: buildUserPublicProfile(entry.userId),
      sourceUser: buildUserPublicProfile(entry.sourceUserId),
      topupExtRef: entry.topupExtRef || null,
    }));

    return res.json({ page, limit, total, items });
  } catch (err) {
    console.error('admin referrals pending error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/referrals/withdrawals', async (req, res) => {
  try {
    const { limit, skip, page } = parsePagination(req.query);
    const query = {};
    const statusRaw = typeof req.query.status === 'string' ? req.query.status.trim().toLowerCase() : 'pending';
    if (statusRaw && statusRaw !== 'all') {
      const allowed = new Set(['pending', 'paid', 'cancelled']);
      if (!allowed.has(statusRaw)) {
        return res.status(400).json({ error: 'invalid_status' });
      }
      query.status = statusRaw;
    }
    const userId = toObjectId(req.query.userId);
    if (userId) {
      query.userId = userId;
    }

    const [requests, total] = await Promise.all([
      ReferralWithdrawalRequest.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate('userId', 'name email phone role')
        .populate('processedBy', 'name email phone role')
        .lean(),
      ReferralWithdrawalRequest.countDocuments(query),
    ]);

    return res.json({
      page,
      limit,
      total,
      items: requests.map(buildWithdrawalPayload),
    });
  } catch (err) {
    console.error('admin withdrawal list error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

// Export referral withdrawal requests as CSV for reconciliation
router.get('/referrals/withdrawals/export.csv', async (req, res) => {
  try {
    const query = {};
    // Default: include all statuses. Use ?status=pending|paid|cancelled to filter; status=all or empty means no filter.
    const statusRaw = typeof req.query.status === 'string' ? req.query.status.trim().toLowerCase() : '';
    if (statusRaw && statusRaw !== 'all') {
      const allowed = new Set(['pending', 'paid', 'cancelled']);
      if (!allowed.has(statusRaw)) {
        return res.status(400).json({ error: 'invalid_status' });
      }
      query.status = statusRaw;
    }
    const userId = toObjectId(req.query.userId);
    if (userId) {
      query.userId = userId;
    }

    const requests = await ReferralWithdrawalRequest.find(query)
      .sort({ createdAt: -1 })
      .populate('userId', 'name email phone role')
      .populate('processedBy', 'name email phone role')
      .lean();

    const rows = [];
    const header = [
      'id',
      'userName',
      'userEmail',
      'userPhone',
      'amountPaise',
      'amountRupees',
      'method',
      'upiId',
      'bankAccountName',
      'bankAccountNumber',
      'bankIfsc',
      'bankName',
      'contactName',
      'contactMobile',
      'status',
      'paymentRef',
      'adminNote',
      'createdAt',
      'processedAt',
      'processedByName',
    ];
    rows.push(header);

    const asTextCell = (v) => {
      if (v === null || v === undefined || v === '') return '';
      const str = String(v);
      // Force Excel/Sheets to keep digits intact (no scientific notation/rounding)
      if (/^\d+$/.test(str)) return `="${str}"`;
      return str;
    };

    function toCsvValue(v, { forceText = false } = {}) {
      if (v === null || v === undefined) return '';
      const raw = forceText ? asTextCell(v) : String(v);
      if (raw.includes(',') || raw.includes('"') || raw.includes('\n')) {
        return `"${raw.replace(/"/g, '""')}"`;
      }
      return raw;
    }

    requests.forEach((doc) => {
      const user = doc.userId || {};
      const processedBy = doc.processedBy || {};
      const row = [
        doc._id,
        user.name || '',
        user.email || '',
        toCsvValue(user.phone || '', { forceText: true }),
        doc.amountPaise || 0,
        Math.floor((doc.amountPaise || 0) / 100),
        doc.method || '',
        doc.upiId || '',
        doc.bankAccountName || '',
        toCsvValue(doc.bankAccountNumber || '', { forceText: true }),
        doc.bankIfsc || '',
        doc.bankName || '',
        doc.contactName || '',
        toCsvValue(doc.contactMobile || '', { forceText: true }),
        doc.status || '',
        doc.paymentRef || '',
        doc.adminNote || '',
        doc.createdAt ? new Date(doc.createdAt).toISOString() : '',
        doc.processedAt ? new Date(doc.processedAt).toISOString() : '',
        processedBy.name || (processedBy._id ? String(processedBy._id) : ''),
      ];
      // row already has escaped text cells; apply base CSV escaping
      rows.push(row.map((cell) => toCsvValue(cell, { forceText: false })).join(','));
    });

    const csv = rows.map((r) => (Array.isArray(r) ? r.join(',') : r)).join('\n');
    const filename = `referral_withdrawals_${new Date().toISOString().slice(0, 10)}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.status(200).send(csv);
  } catch (err) {
    console.error('admin withdrawal export error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.patch('/referrals/withdrawals/:requestId', async (req, res) => {
  const { requestId } = req.params;
  if (!mongoose.Types.ObjectId.isValid(requestId)) {
    return res.status(400).json({ error: 'invalid_request_id' });
  }

  const statusRaw = typeof req.body?.status === 'string' ? req.body.status.trim().toLowerCase() : '';
  const allowed = new Set(['paid', 'cancelled']);
  if (!allowed.has(statusRaw)) {
    return res.status(400).json({ error: 'invalid_status' });
  }

  const adminNote = typeof req.body?.adminNote === 'string' && req.body.adminNote.trim()
    ? req.body.adminNote.trim()
    : undefined;
  const paymentRef = typeof req.body?.paymentRef === 'string' && req.body.paymentRef.trim()
    ? req.body.paymentRef.trim()
    : undefined;

  const session = await mongoose.startSession();
  let updatedRequest = null;
  try {
    await session.withTransaction(async () => {
      const request = await ReferralWithdrawalRequest.findOne({
        _id: requestId,
        status: 'pending',
      })
        .session(session);

      if (!request) {
        const err = new Error('REQUEST_NOT_FOUND');
        err.code = 'REQUEST_NOT_FOUND';
        throw err;
      }

      const ledgerIds = Array.isArray(request.ledgerEntryIds) ? request.ledgerEntryIds : [];
      if (statusRaw === 'paid') {
        if (ledgerIds.length) {
          await ReferralLedger.updateMany(
            { _id: { $in: ledgerIds } },
            { $set: { status: 'paid' } },
            { session },
          );
        }
        request.status = 'paid';
        if (paymentRef !== undefined) request.paymentRef = paymentRef;
      } else if (statusRaw === 'cancelled') {
        if (ledgerIds.length) {
          await ReferralLedger.updateMany(
            { _id: { $in: ledgerIds } },
            { $set: { status: 'pending' }, $unset: { withdrawalRequestId: '' } },
            { session },
          );
        }
        request.status = 'cancelled';
      }

      request.processedAt = new Date();
      request.processedBy = req.user.id;
      if (adminNote !== undefined) {
        request.adminNote = adminNote;
      }
      await request.save({ session });

      updatedRequest = request.toObject();
    });
  } catch (err) {
    if (err?.code === 'REQUEST_NOT_FOUND') {
      await session.endSession();
      return res.status(404).json({ error: 'request_not_found_or_already_processed' });
    }
    await session.endSession();
    console.error('admin withdrawal update error', err);
    return res.status(500).json({ error: 'server error' });
  }

  await session.endSession();

  const populated = await ReferralWithdrawalRequest.findById(updatedRequest._id)
    .populate('userId', 'name email phone role')
    .populate('processedBy', 'name email phone role')
    .lean();

  return res.json({
    request: buildWithdrawalPayload(populated || updatedRequest),
  });
});

router.get('/users', async (req, res) => {
  try {
    const { limit, skip, page } = parsePagination(req.query);
    const filter = {};
    if (typeof req.query.role === 'string' && ['user', 'admin'].includes(req.query.role)) {
      filter.role = req.query.role;
    }
    if (req.query.search) {
      const term = String(req.query.search).trim();
      filter.$or = [
        { name: { $regex: term, $options: 'i' } },
        { email: { $regex: term, $options: 'i' } },
        { phone: { $regex: term, $options: 'i' } },
        { referralCode: { $regex: term, $options: 'i' } },
      ];
    }

    const [users, total] = await Promise.all([
      User.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .select('name email phone role createdAt lastLoginAt referralCode referralCount loginCount'),
      User.countDocuments(filter),
    ]);

    const userIds = users.map((u) => u._id);
    const [wallets, pendingReferrals] = await Promise.all([
      Wallet.find({ userId: { $in: userIds } }).select('userId balance').lean(),
      ReferralLedger.aggregate([
        { $match: { userId: { $in: userIds }, status: { $in: ['pending', 'requested'] } } },
        { $group: { _id: '$userId', totalPaise: { $sum: '$amountPaise' }, count: { $sum: 1 } } },
      ]),
    ]);

    const walletMap = new Map(wallets.map((w) => [String(w.userId), w]));
    const pendingMap = new Map(pendingReferrals.map((entry) => [String(entry._id), entry]));

    const items = users.map((user) => {
      const wallet = walletMap.get(String(user._id));
      const pending = pendingMap.get(String(user._id));
      return {
        ...buildUserPublicProfile(user),
        walletBalancePaise: wallet?.balance ?? 0,
        walletBalanceRupees: toRupees(wallet?.balance ?? 0),
        pendingReferralPaise: pending?.totalPaise ?? 0,
        pendingReferralApproxRupees: toRupees(pending?.totalPaise ?? 0),
        pendingReferralCount: pending?.count ?? 0,
      };
    });

    return res.json({ page, limit, total, items });
  } catch (err) {
    console.error('admin users list error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/users/:userId', async (req, res) => {
  try {
    const userId = toObjectId(req.params.userId);
    if (!userId) {
      return res.status(400).json({ error: 'invalid_user_id' });
    }

    const { from, to } = parseDateRange(req.query);
    const depthRaw = Number.parseInt(req.query.depth ?? req.query.levelDepth ?? '10', 10);
    const depth = Number.isFinite(depthRaw) && depthRaw > 0 ? Math.min(depthRaw, 10) : 10;

    const [user, wallet, referralStats, recentPurchases, recentLedger] = await Promise.all([
      User.findById(userId)
        .select(
          'name email phone role createdAt lastLoginAt referralCode referralCount loginCount lastLoginIp',
        )
        .lean(),
      Wallet.findOne({ userId }).lean(),
      ReferralLedger.aggregate([
        { $match: { userId } },
        {
          $group: {
            _id: '$status',
            totalPaise: { $sum: '$amountPaise' },
            count: { $sum: 1 },
          },
        },
      ]),
      Purchase.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(20)
        .populate('advice', 'category price text')
        .lean(),
      WalletLedger.find({ userId })
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
    ]);

    if (!user) {
      return res.status(404).json({ error: 'user_not_found' });
    }

    const referralStatMap = referralStats.reduce((acc, stat) => {
      acc[stat._id] = {
        count: stat.count,
        paise: stat.totalPaise,
        rupees: toRupees(stat.totalPaise),
      };
      return acc;
    }, {});

    const pendingStatsRaw = referralStatMap.pending || { count: 0, paise: 0, rupees: 0 };
    const requestedStatsRaw = referralStatMap.requested || { count: 0, paise: 0, rupees: 0 };
    const pendingCombinedPaise = (pendingStatsRaw.paise || 0) + (requestedStatsRaw.paise || 0);
    const pendingSummary = {
      count: (pendingStatsRaw.count || 0) + (requestedStatsRaw.count || 0),
      paise: pendingCombinedPaise,
      rupees: toRupees(pendingCombinedPaise),
    };

    const purchases = recentPurchases.map((purchase) => {
      const amountPaise = Number.isFinite(purchase.amountPaise)
        ? purchase.amountPaise
        : Number.isFinite(purchase.amount)
          ? Math.round(purchase.amount * 100)
          : 0;
      return {
        id: purchase._id,
        createdAt: purchase.createdAt,
        amountPaise,
        amountRupees: toRupees(amountPaise),
        note: purchase.note || null,
        category: purchase.category || purchase.advice?.category || null,
        title: purchase.title || purchase.advice?.text || null,
      };
    });

    const ledger = recentLedger.map((entry) => ({
      id: entry._id,
      type: entry.type,
      amountPaise: entry.amount,
      amountRupees: toRupees(entry.amount),
      note: entry.note || null,
      extRef: entry.extRef || null,
      metadata: entry.metadata || null,
      createdAt: entry.createdAt,
    }));

    const { levels, usedClosure } = await loadReferralTreeNodes(userId, depth);

    const descendantIdSet = new Map();
    levels.forEach((ids) => {
      ids.forEach((id) => {
        if (id) descendantIdSet.set(id.toString(), id);
      });
    });
    const descendantIds = Array.from(descendantIdSet.values());

    const [descendantUsers, bonusAgg] = await Promise.all([
      descendantIds.length
        ? User.find({ _id: { $in: descendantIds } })
            .select('name email phone role createdAt lastLoginAt referralCode referralCount')
            .lean()
        : [],
      descendantIds.length
        ? BonusPayout.aggregate([
            {
              $match: {
                uplineUserId: userId,
                downlineUserId: { $in: descendantIds },
              },
            },
            {
              $addFields: {
                effectiveAt: {
                  $cond: [
                    {
                      $and: [
                        { $in: ['$status', ['RELEASED', 'REVERSED']] },
                        { $ifNull: ['$processedAt', false] },
                      ],
                    },
                    '$processedAt',
                    '$createdAt',
                  ],
                },
              },
            },
            ...(from || to
              ? [
                  {
                    $match: {
                      effectiveAt: {
                        ...(from ? { $gte: from } : {}),
                        ...(to ? { $lte: to } : {}),
                      },
                    },
                  },
                ]
              : []),
            {
              $group: {
                _id: {
                  downline: '$downlineUserId',
                  status: '$status',
                  level: '$level',
                },
                amountPaise: { $sum: '$amountPaise' },
                count: { $sum: 1 },
              },
            },
          ])
        : [],
    ]);

    const userMap = new Map(
      descendantUsers.map((doc) => [doc._id.toString(), doc]),
    );

    const earningsByDownline = new Map();
    bonusAgg.forEach((row) => {
      const downlineId = row._id?.downline?.toString();
      const status = typeof row._id?.status === 'string' ? row._id.status.toUpperCase() : null;
      const level = ensureInt(row._id?.level);
      if (!downlineId || !status || !level) return;
      if (!earningsByDownline.has(downlineId)) {
        earningsByDownline.set(downlineId, {
          pending: { amountPaise: 0, count: 0 },
          released: { amountPaise: 0, count: 0 },
          reversed: { amountPaise: 0, count: 0 },
          level,
        });
      }
      const record = earningsByDownline.get(downlineId);
      const amountPaise = ensureNumber(row.amountPaise);
      const count = ensureInt(row.count);
      if (status === 'PENDING') {
        record.pending.amountPaise += amountPaise;
        record.pending.count += count;
      } else if (status === 'RELEASED') {
        record.released.amountPaise += amountPaise;
        record.released.count += count;
      } else if (status === 'REVERSED') {
        record.reversed.amountPaise += amountPaise;
        record.reversed.count += count;
      }
    });

    const levelsResponse = [];
    for (let lvl = 1; lvl <= depth; lvl += 1) {
      const ids = levels.get(lvl) || [];
      const descendants = ids.map((id) => {
        const key = id.toString();
        const duser = userMap.get(key);
        const earnings = earningsByDownline.get(key) || {
          pending: { amountPaise: 0, count: 0 },
          released: { amountPaise: 0, count: 0 },
          reversed: { amountPaise: 0, count: 0 },
        };
        const normalizeEarnings = (entry) => ({
          amountPaise: ensureNumber(entry.amountPaise),
          amountRupees: toRupees(entry.amountPaise),
          count: ensureInt(entry.count),
        });
        return {
          id,
          user: buildUserPublicProfile(duser),
          earnings: {
            pending: normalizeEarnings(earnings.pending || {}),
            released: normalizeEarnings(earnings.released || {}),
            reversed: normalizeEarnings(earnings.reversed || {}),
          },
        };
      });
      levelsResponse.push({
        level: lvl,
        descendantCount: descendants.length,
        descendants,
      });
    }

    return res.json({
      user: buildUserPublicProfile(user),
      login: {
        lastLoginAt: user.lastLoginAt || null,
        lastLoginIp: user.lastLoginIp || null,
      },
      wallet: {
        balancePaise: wallet?.balance ?? 0,
        balanceRupees: toRupees(wallet?.balance ?? 0),
      },
      referrals: {
        pending: pendingSummary,
        requested: referralStatMap.requested || { count: 0, paise: 0, rupees: 0 },
        paid: referralStatMap.paid || { count: 0, paise: 0, rupees: 0 },
        cancelled: referralStatMap.cancelled || { count: 0, paise: 0, rupees: 0 },
      },
      recentPurchases: purchases,
      recentLedger: ledger,
      referralTree: {
        timeframe: {
          from: from ? from.toISOString() : null,
          to: to ? to.toISOString() : null,
        },
        depth,
        usedClosure,
        levels: levelsResponse,
      },
    });
  } catch (err) {
    console.error('admin user detail error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

// Admin utility: seed demo users who are always active, can refer, but cannot withdraw referral amounts
// POST /api/admin/demo/users/seed  { count?: number, baseEmail?: string, password?: string }
router.post('/demo/users/seed', async (req, res) => {
  try {
    const countRaw = Number.parseInt(req.body?.count ?? '7', 10);
    const count = Number.isFinite(countRaw) ? Math.min(Math.max(countRaw, 1), 50) : 7;
    const baseEmail = (req.body?.baseEmail || 'demo{{n}}@test.com').toString();
    const password = (req.body?.password || 'Demo@12345').toString();

    const created = [];
    for (let i = 1; i <= count; i += 1) {
      const email = baseEmail.includes('{{n}}')
        ? baseEmail.replace(/\{\{n\}\}/g, String(i))
        : baseEmail.replace('@', `+${i}@`);

      const emailNorm = email.trim().toLowerCase();
      let user = await User.findOne({ email: emailNorm });
      const passwordHash = await bcrypt.hash(password, 10);

      if (!user) {
        user = new User({
          name: `Demo ${i}`,
          email: emailNorm,
          passwordHash,
          role: 'user',
          isDemo: true,
          accountStatus: 'ACTIVE',
          accountActivatedAt: new Date(),
          accountActiveUntil: new Date('2099-12-31T23:59:59.999Z'),
        });
        await ensureReferralCode(user);
        await user.save();
      } else {
        // Update existing to ensure demo flags and active status; also reset password
        user.isDemo = true;
        user.passwordHash = passwordHash;
        user.accountStatus = 'ACTIVE';
        user.accountActivatedAt = user.accountActivatedAt || new Date();
        user.accountActiveUntil = new Date('2099-12-31T23:59:59.999Z');
        await ensureReferralCode(user);
        await user.save();
      }

      created.push({
        id: user._id,
        name: user.name,
        email: user.email,
        password,
        referralCode: user.referralCode,
        isDemo: true,
        accountStatus: user.accountStatus,
        accountActiveUntil: user.accountActiveUntil,
      });
    }

    return res.status(201).json({ count: created.length, users: created });
  } catch (err) {
    console.error('admin demo users seed error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/users/:userId/wallet-ledger', async (req, res) => {
  try {
    const userId = toObjectId(req.params.userId);
    if (!userId) return res.status(400).json({ error: 'invalid_user_id' });

    const { page, pageSize, limit, skip } = parsePagination(req.query);
    const { from, to } = parseDateRange(req.query);

    const match = { userId };
    if (from || to) {
      match.createdAt = {};
      if (from) match.createdAt.$gte = from;
      if (to) match.createdAt.$lte = to;
    }

    const rawTypeParam = req.query.type ?? req.query.types;
    if (rawTypeParam) {
      const normalizedTypes = String(rawTypeParam)
        .split(',')
        .map((part) => normalizeLedgerType(part.trim().toUpperCase()))
        .filter(Boolean);
      if (normalizedTypes.length) {
        const expanded = expandLedgerTypes(normalizedTypes);
        match.$or = [
          { type: { $in: expanded } },
          { normalizedType: { $in: expanded } },
        ];
      }
    }

    const [entries, total] = await Promise.all([
      WalletLedger.find(match)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      WalletLedger.countDocuments(match),
    ]);

    const items = entries.map((entry) => {
      const normalized = normalizeLedgerType(entry.normalizedType || entry.type);
      const amountPaise = ensureNumber(entry.amount);
      return {
        id: entry._id,
        type: normalized || entry.type,
        rawType: entry.type,
        amountPaise,
        amountRupees: toRupees(amountPaise),
        note: entry.note || null,
        metadata: entry.metadata || null,
        extRef: entry.extRef || null,
        createdAt: entry.createdAt,
      };
    });

    return res.json({
      page,
      pageSize: pageSize || limit,
      limit,
      total,
      timeframe: {
        from: from ? from.toISOString() : null,
        to: to ? to.toISOString() : null,
      },
      items,
    });
  } catch (err) {
    console.error('admin user ledger error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/users/:userId/referrals', async (req, res) => {
  try {
    const userId = toObjectId(req.params.userId);
    if (!userId) return res.status(400).json({ error: 'invalid_user_id' });

    const { limit, skip, page } = parsePagination(req.query);
    const query = { userId };
    if (typeof req.query.status === 'string' && ['pending', 'requested', 'paid', 'cancelled'].includes(req.query.status)) {
      query.status = req.query.status;
    }

    const [entries, total] = await Promise.all([
      ReferralLedger.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate('sourceUserId', 'name email phone')
        .lean(),
      ReferralLedger.countDocuments(query),
    ]);

    const items = entries.map((entry) => ({
      id: entry._id,
      level: entry.level,
      amountPaise: entry.amountPaise,
      amountRupees: toRupees(entry.amountPaise),
      status: entry.status,
      note: entry.note || null,
      createdAt: entry.createdAt,
      sourceUser: buildUserPublicProfile(entry.sourceUserId),
      topupExtRef: entry.topupExtRef || null,
      withdrawalRequestId: entry.withdrawalRequestId || null,
    }));

    return res.json({ page, limit, total, items });
  } catch (err) {
    console.error('admin user referrals error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/daily-tip', async (req, res) => {
  try {
    const message =
      typeof req.body?.message === 'string' ? req.body.message.trim() : '';
    if (!message) return res.status(400).json({ error: 'message_required' });

    const createdBy = toObjectId(req.user?.id);
    const tip = await DailyTip.create({
      message,
      createdBy: createdBy || undefined,
    });

    const payload = {
      id: tip._id,
      message: tip.message,
      publishedAt: tip.publishedAt,
      createdAt: tip.createdAt,
      createdBy: createdBy ? { id: createdBy.toString() } : null,
    };

    const io = req.app?.get('io');
    if (io && typeof io.emit === 'function') {
      io.emit('daily-tip:new', payload);
    }

    return res.status(201).json({ ok: true, tip: payload });
  } catch (err) {
    console.error('admin daily tip create error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/daily-tip', async (req, res) => {
  try {
    const { limit, skip, page } = parsePagination(req.query);

    const [itemsRaw, total] = await Promise.all([
      DailyTip.find({})
        .sort({ publishedAt: -1, createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate('createdBy', 'name email phone role createdAt lastLoginAt')
        .lean(),
      DailyTip.countDocuments({}),
    ]);

    const items = itemsRaw.map((doc) => ({
      id: doc._id,
      message: doc.message,
      publishedAt: doc.publishedAt,
      createdAt: doc.createdAt,
      createdBy: doc.createdBy ? buildUserPublicProfile(doc.createdBy) : null,
    }));

    return res.json({ page, limit, total, items });
  } catch (err) {
    console.error('admin daily tip list error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.patch('/users/:userId/password', async (req, res) => {
  try {
    const userId = toObjectId(req.params.userId);
    if (!userId) return res.status(400).json({ error: 'invalid_user_id' });

    const newPassword = req.body?.newPassword;
    if (typeof newPassword !== 'string' || newPassword.length < 8 || newPassword.length > 128) {
      return res.status(400).json({ error: 'password_must_be_8_128_chars' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'user_not_found' });
    }

    user.passwordHash = await bcrypt.hash(newPassword, 12);
    await user.save();

    return res.json({ ok: true });
  } catch (err) {
    console.error('admin user password error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;
