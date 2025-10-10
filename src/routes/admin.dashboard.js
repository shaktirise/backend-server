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

const router = express.Router();

router.use(auth, admin);

function toObjectId(value) {
  if (typeof value !== 'string') return null;
  if (mongoose.Types.ObjectId.isValid(value)) {
    return new mongoose.Types.ObjectId(value);
  }
  return null;
}

function parseDate(value) {
  if (!value) return null;
  const ts = Date.parse(value);
  if (Number.isNaN(ts)) return null;
  return new Date(ts);
}

function parsePagination(query) {
  const limitRaw = Number.parseInt(query.limit ?? '25', 10);
  const pageRaw = Number.parseInt(query.page ?? '1', 10);
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 200) : 25;
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? pageRaw : 1;
  const skip = (page - 1) * limit;
  return { limit, page, skip };
}

function toIntRupees(paise) {
  const value = Number.isFinite(paise) ? paise : 0;
  return Math.floor(value / 100);
}

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
  };
}

function buildWithdrawalPayload(doc) {
  if (!doc) return null;
  return {
    id: doc._id,
    user: buildUserPublicProfile(doc.userId),
    amountPaise: doc.amountPaise,
    amountRupees: toIntRupees(doc.amountPaise),
    status: doc.status,
    note: doc.note || null,
    adminNote: doc.adminNote || null,
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

router.get('/dashboard/overview', async (req, res) => {
  try {
    const now = new Date();
    const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    const [
      totalUsers,
      active24h,
      active7d,
      newDaily,
      newWeekly,
      newMonthly,
      walletAgg,
      referralPaidAgg,
      referralPendingAgg,
      purchaseCount,
      topReferrersRaw,
      topReferralEarnersRaw,
      recentCallsRaw,
      recentTopupsRaw,
      withdrawalPendingAgg,
      recentWithdrawalsRaw,
    ] = await Promise.all([
      User.countDocuments({}),
      User.countDocuments({ lastLoginAt: { $gte: dayAgo } }),
      User.countDocuments({ lastLoginAt: { $gte: weekAgo } }),
      User.countDocuments({ createdAt: { $gte: dayAgo } }),
      User.countDocuments({ createdAt: { $gte: weekAgo } }),
      User.countDocuments({ createdAt: { $gte: monthAgo } }),
      Wallet.aggregate([
        { $group: { _id: null, balancePaise: { $sum: '$balance' }, wallets: { $sum: 1 } } },
      ]),
      ReferralLedger.aggregate([
        { $match: { status: 'paid' } },
        { $group: { _id: null, totalPaise: { $sum: '$amountPaise' }, count: { $sum: 1 } } },
      ]),
      ReferralLedger.aggregate([
        { $match: { status: { $in: ['pending', 'requested'] } } },
        { $group: { _id: null, totalPaise: { $sum: '$amountPaise' }, count: { $sum: 1 } } },
      ]),
      Purchase.countDocuments({}),
      User.find({}).sort({ referralCount: -1 }).limit(10).select('name email phone referralCode referralCount role createdAt lastLoginAt').lean(),
      ReferralLedger.aggregate([
        { $match: { status: 'paid' } },
        {
          $group: {
            _id: '$userId',
            totalPaise: { $sum: '$amountPaise' },
            payoutCount: { $sum: 1 },
          },
        },
        { $sort: { totalPaise: -1 } },
        { $limit: 10 },
      ]),
      Purchase.find({})
        .sort({ createdAt: -1 })
        .limit(10)
        .populate('user', 'name email phone')
        .populate('advice', 'category price createdAt text')
        .lean(),
      WalletLedger.find({ type: 'TOPUP' })
        .sort({ createdAt: -1 })
        .limit(10)
        .populate('userId', 'name email phone')
        .lean(),
      ReferralWithdrawalRequest.aggregate([
        { $match: { status: 'pending' } },
        { $group: { _id: null, totalPaise: { $sum: '$amountPaise' }, count: { $sum: 1 } } },
      ]),
      ReferralWithdrawalRequest.find({})
        .sort({ createdAt: -1 })
        .limit(10)
        .populate('userId', 'name email phone')
        .lean(),
    ]);

    const walletStats = walletAgg[0] || { balancePaise: 0, wallets: 0 };
    const referralPaidStats = referralPaidAgg[0] || { totalPaise: 0, count: 0 };
    const referralPendingStats = referralPendingAgg[0] || { totalPaise: 0, count: 0 };
    const withdrawalPendingStats = withdrawalPendingAgg[0] || { totalPaise: 0, count: 0 };

    const topReferrers = topReferrersRaw.map((user) => ({
      ...buildUserPublicProfile(user),
      totalReferrals: user.referralCount || 0,
    }));

    const topEarnerIds = topReferralEarnersRaw.map((row) => row._id).filter(Boolean);
    const earnerUsers = topEarnerIds.length
      ? await User.find({ _id: { $in: topEarnerIds } })
          .select('name email phone referralCode role')
          .lean()
      : [];
    const earnerUserMap = new Map(earnerUsers.map((u) => [String(u._id), u]));
    const topReferralEarners = topReferralEarnersRaw.map((row) => {
      const user = earnerUserMap.get(String(row._id));
      return {
        user: buildUserPublicProfile(user),
        approxAmountRupees: toIntRupees(row.totalPaise),
        totalPayouts: row.payoutCount || 0,
      };
    });

    const recentCalls = recentCallsRaw.map((purchase) => {
      const amountPaise = Number.isFinite(purchase.amountPaise)
        ? purchase.amountPaise
        : Number.isFinite(purchase.amount)
          ? Math.round(purchase.amount * 100)
          : 0;
      return {
        id: purchase._id,
        createdAt: purchase.createdAt,
        amountPaise,
        amountRupees: toIntRupees(amountPaise),
        note: purchase.note || null,
        category: purchase.category || purchase.advice?.category || null,
        title: purchase.title || purchase.advice?.text || null,
        user: buildUserPublicProfile(purchase.user),
      };
    });

    const recentTopups = recentTopupsRaw.map((entry) => ({
      id: entry._id,
      createdAt: entry.createdAt,
      amountPaise: entry.amount || 0,
      amountRupees: toIntRupees(entry.amount || 0),
      note: entry.note || null,
      user: buildUserPublicProfile(entry.userId),
      extRef: entry.extRef || null,
    }));

    const recentWithdrawals = recentWithdrawalsRaw.map(buildWithdrawalPayload);

    return res.json({
      totals: {
        users: totalUsers,
        purchases: purchaseCount,
      },
      activeUsers: {
        last24h: active24h,
        last7d: active7d,
      },
      newSignups: {
        last24h: newDaily,
        last7d: newWeekly,
        last30d: newMonthly,
      },
      wallet: {
        totalBalancePaise: walletStats.balancePaise || 0,
        totalBalanceRupees: toIntRupees(walletStats.balancePaise || 0),
        walletCount: walletStats.wallets || 0,
      },
      referrals: {
        totalPaidPaise: referralPaidStats.totalPaise || 0,
        totalPaidRupees: toIntRupees(referralPaidStats.totalPaise || 0),
        totalPaidCount: referralPaidStats.count || 0,
        pendingPaise: referralPendingStats.totalPaise || 0,
        pendingApproxRupees: toIntRupees(referralPendingStats.totalPaise || 0),
        pendingCount: referralPendingStats.count || 0,
      },
      topReferrers,
      topReferralEarners,
      recentCalls,
      recentTopups,
      withdrawals: {
        pendingPaise: withdrawalPendingStats.totalPaise || 0,
        pendingApproxRupees: toIntRupees(withdrawalPendingStats.totalPaise || 0),
        pendingCount: withdrawalPendingStats.count || 0,
        recentRequests: recentWithdrawals,
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
        amountRupees: toIntRupees(amountPaise),
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
    const { limit, skip, page } = parsePagination(req.query);
    const query = {};
    const userId = toObjectId(req.query.userId);
    if (userId) {
      query.userId = userId;
    }
    const type = typeof req.query.type === 'string' ? req.query.type.trim().toUpperCase() : null;
    if (type && ['TOPUP', 'PURCHASE', 'REFERRAL'].includes(type)) {
      query.type = type;
    }
    const startDate = parseDate(req.query.start);
    const endDate = parseDate(req.query.end);
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = startDate;
      if (endDate) query.createdAt.$lte = endDate;
    }

    const [entries, total] = await Promise.all([
      WalletLedger.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate('userId', 'name email phone')
        .populate('walletId', 'userId')
        .lean(),
      WalletLedger.countDocuments(query),
    ]);

    const items = entries.map((entry) => ({
      id: entry._id,
      type: entry.type,
      amountPaise: entry.amount,
      amountRupees: toIntRupees(entry.amount),
      note: entry.note || null,
      extRef: entry.extRef || null,
      metadata: entry.metadata || null,
      createdAt: entry.createdAt,
      user: buildUserPublicProfile(entry.userId),
    }));

    return res.json({
      page,
      limit,
      total,
      items,
    });
  } catch (err) {
    console.error('admin wallet ledger error', err);
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
      amountRupees: toIntRupees(entry.amountPaise),
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
        walletBalanceRupees: toIntRupees(wallet?.balance ?? 0),
        pendingReferralPaise: pending?.totalPaise ?? 0,
        pendingReferralApproxRupees: toIntRupees(pending?.totalPaise ?? 0),
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
        rupees: toIntRupees(stat.totalPaise),
      };
      return acc;
    }, {});

    const pendingStatsRaw = referralStatMap.pending || { count: 0, paise: 0, rupees: 0 };
    const requestedStatsRaw = referralStatMap.requested || { count: 0, paise: 0, rupees: 0 };
    const pendingCombinedPaise = (pendingStatsRaw.paise || 0) + (requestedStatsRaw.paise || 0);
    const pendingSummary = {
      count: (pendingStatsRaw.count || 0) + (requestedStatsRaw.count || 0),
      paise: pendingCombinedPaise,
      rupees: toIntRupees(pendingCombinedPaise),
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
        amountRupees: toIntRupees(amountPaise),
        note: purchase.note || null,
        category: purchase.category || purchase.advice?.category || null,
        title: purchase.title || purchase.advice?.text || null,
      };
    });

    const ledger = recentLedger.map((entry) => ({
      id: entry._id,
      type: entry.type,
      amountPaise: entry.amount,
      amountRupees: toIntRupees(entry.amount),
      note: entry.note || null,
      extRef: entry.extRef || null,
      metadata: entry.metadata || null,
      createdAt: entry.createdAt,
    }));

    return res.json({
      user: buildUserPublicProfile(user),
      login: {
        lastLoginAt: user.lastLoginAt || null,
        lastLoginIp: user.lastLoginIp || null,
      },
      wallet: {
        balancePaise: wallet?.balance ?? 0,
        balanceRupees: toIntRupees(wallet?.balance ?? 0),
      },
      referrals: {
        pending: pendingSummary,
        requested: referralStatMap.requested || { count: 0, paise: 0, rupees: 0 },
        paid: referralStatMap.paid || { count: 0, paise: 0, rupees: 0 },
        cancelled: referralStatMap.cancelled || { count: 0, paise: 0, rupees: 0 },
      },
      recentPurchases: purchases,
      recentLedger: ledger,
    });
  } catch (err) {
    console.error('admin user detail error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/users/:userId/wallet-ledger', async (req, res) => {
  try {
    const userId = toObjectId(req.params.userId);
    if (!userId) return res.status(400).json({ error: 'invalid_user_id' });

    const { limit, skip, page } = parsePagination(req.query);
    const query = { userId };
    const type = typeof req.query.type === 'string' ? req.query.type.trim().toUpperCase() : null;
    if (type && ['TOPUP', 'PURCHASE', 'REFERRAL'].includes(type)) {
      query.type = type;
    }

    const [entries, total] = await Promise.all([
      WalletLedger.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      WalletLedger.countDocuments(query),
    ]);

    const items = entries.map((entry) => ({
      id: entry._id,
      type: entry.type,
      amountPaise: entry.amount,
      amountRupees: toIntRupees(entry.amount),
      note: entry.note || null,
      metadata: entry.metadata || null,
      extRef: entry.extRef || null,
      createdAt: entry.createdAt,
    }));

    return res.json({ page, limit, total, items });
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
      amountRupees: toIntRupees(entry.amountPaise),
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

    let publishedAt = parseDate(req.body?.publishedAt);
    if (!publishedAt) {
      publishedAt = new Date();
    }

    const createdBy = toObjectId(req.user?.id);
    const tip = await DailyTip.create({
      message,
      publishedAt,
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
