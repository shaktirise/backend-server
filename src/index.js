import express from 'express';
import http from 'http';
import cors from 'cors';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import { Server } from 'socket.io';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import bodyParser from 'body-parser';
import crypto from 'crypto';

import { connectDB } from './config/db.js';
import authRoutes from './routes/auth.js';
import adviceRoutes from './routes/advice.js';
import walletRoutes from './routes/wallet.v2.js';
import segmentRoutes from './routes/segments.js';
import imageRoutes from './routes/images.js';
import adminDashboardRoutes from './routes/admin.dashboard.js';
import dailyTipRoutes from './routes/dailyTip.js';
import Wallet from './models/Wallet.js';
import WalletLedger from './models/WalletLedger.js';
import { WALLET_LEDGER_TYPES } from './constants/walletLedger.js';

dotenv.config();

function parseOrigins(value) {
  const list = String(value || '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
  // Treat '*' specially as allow-all
  if (list.includes('*')) return ['*'];
  return list;
}

function escapeRegExp(value) {
  return value.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&');
}

function compileOriginMatcher(pattern) {
  if (pattern.includes('*')) {
    const source = `^${pattern
      .split('*')
      .map((segment) => escapeRegExp(segment))
      .join('.*')}$`;
    const regex = new RegExp(source);
    return (origin) => regex.test(origin);
  }

  try {
    const parsed = new URL(pattern);
    const allowAnyPort =
      !parsed.port && (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1');

    return (origin) => {
      try {
        const candidate = new URL(origin);
        if (allowAnyPort) {
          return (
            candidate.protocol === parsed.protocol && candidate.hostname === parsed.hostname
          );
        }
        return candidate.origin === parsed.origin;
      } catch (err) {
        return origin === pattern;
      }
    };
  } catch (err) {
    return (origin) => origin === pattern;
  }
}

function createOriginMatcher(list) {
  const allowAll = list.length === 0 || list[0] === '*';
  const matchers = allowAll ? [] : list.map((pattern) => compileOriginMatcher(pattern));

  return {
    allowAll,
    matches(origin) {
      if (!origin) return true;
      if (allowAll) return true;
      return matchers.some((matcher) => matcher(origin));
    },
  };
}

const httpOrigins = parseOrigins(process.env.CORS_ALLOWED_ORIGINS);
const socketOrigins = parseOrigins(process.env.SOCKET_ALLOWED_ORIGINS);
const httpOriginMatcher = createOriginMatcher(httpOrigins);
const socketOriginMatcher = createOriginMatcher(socketOrigins.length ? socketOrigins : httpOrigins);

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      if (socketOriginMatcher.matches(origin)) {
        return callback(null, true);
      }
      console.warn(`Blocked Socket.IO origin: ${origin}`);
      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
  },
});

app.set('io', io);
app.set('trust proxy', 1);

const corsOptions = {
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (httpOriginMatcher.matches(origin)) return callback(null, true);
    console.warn(`Blocked CORS origin: ${origin}`);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
// Razorpay webhook must read raw body before JSON parser
app.post('/api/webhooks/razorpay', bodyParser.raw({ type: '*/*' }), async (req, res) => {
  try {
    const signature = req.headers['x-razorpay-signature'];
    if (!signature) return res.status(400).json({ error: 'missing_signature' });

    const secret = process.env.WEBHOOK_SECRET || '';
    const computed = crypto.createHmac('sha256', secret).update(req.body).digest('base64');
    if (computed !== signature) {
      return res.status(400).json({ error: 'invalid_signature' });
    }

    const evt = JSON.parse(req.body.toString('utf8'));
    if (evt?.event === 'payment.captured') {
      const payment = evt?.payload?.payment?.entity || {};
      const paymentId = payment.id;
      const amount = Number(payment.amount);
      const userId = payment?.notes?.userId;

      if (paymentId && Number.isFinite(amount) && amount > 0 && userId) {
        const exists = await WalletLedger.findOne({ extRef: paymentId }).lean();
        if (!exists) {
          const session = await mongoose.startSession();
          try {
            await session.withTransaction(async () => {
              const wallet = await Wallet.findOneAndUpdate(
                { userId },
                { $setOnInsert: { balance: 0 } },
                { upsert: true, new: true, setDefaultsOnInsert: true, session }
              );

              await Wallet.updateOne({ _id: wallet._id }, { $inc: { balance: amount } }, { session });
              await WalletLedger.create([
                {
                  walletId: wallet._id,
                  userId: wallet.userId || userId,
                  type: WALLET_LEDGER_TYPES.DEPOSIT,
                  amount,
                  note: 'Razorpay top-up (webhook)',
                  extRef: paymentId,
                },
              ], { session });
            });
          } finally {
            session.endSession();
          }
        }
      }
    }

    return res.json({ received: true });
  } catch (e) {
    console.error('webhook error', e);
    return res.status(500).json({ error: 'webhook_error' });
  }
});


app.use(express.json({ limit: '10mb' }));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

const rateLimitWindowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
const rateLimitMax = parseInt(process.env.RATE_LIMIT_MAX || '100', 10);
app.use(
  rateLimit({
    windowMs: rateLimitWindowMs,
    max: rateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
  })
);


app.get('/', (req, res) => res.json({ ok: true, service: 'trade-advice-api', uptime: process.uptime() }));
app.get('/api/health', (req, res) => res.json({ ok: true }));
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminDashboardRoutes);
app.use('/api/advice', adviceRoutes);
app.use('/api/wallet', walletRoutes);
app.use('/api/segments', segmentRoutes);
app.use('/api/images', imageRoutes);
app.use('/api/daily-tip', dailyTipRoutes);

app.use((err, req, res, next) => {
  if (err?.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'CORS origin denied' });
  }
  console.error('Unhandled error', err);
  return res.status(500).json({ error: 'internal server error' });
});


io.on('connection', (socket) => {
  const categories = ['STOCKS', 'FUTURE', 'OPTIONS', 'COMMODITY'];
  const timer = setInterval(() => {
    const category = categories[Math.floor(Math.random() * categories.length)];
    const value = Math.round((Math.random() * 1000 + 100) * 100) / 100;
    socket.emit('market:tick', { category, value, ts: Date.now() });
  }, 1500);

  socket.on('disconnect', () => clearInterval(timer));
});

const PORT = parseInt(process.env.PORT || '4000', 10);
const HOST = process.env.HOST || '0.0.0.0';

connectDB()
  .then(() => {
    server.listen(PORT, HOST, () => console.log(`Server listening on http://${HOST}:${PORT}`));
  })
  .catch((err) => {
    console.error('Failed to connect DB', err);
    process.exit(1);
  });

function gracefulShutdown(signal) {
  console.log(`Received ${signal}. Shutting down gracefully...`);
  server.close((serverErr) => {
    if (serverErr) {
      console.error('Error closing HTTP server', serverErr);
      process.exit(1);
    }
    mongoose.connection
      .close(false)
      .then(() => {
        console.log('MongoDB connection closed. Bye!');
        process.exit(0);
      })
      .catch((err) => {
        console.error('Error closing MongoDB connection', err);
        process.exit(1);
      });
  });
}

['SIGTERM', 'SIGINT'].forEach((signal) => {
  process.on(signal, () => gracefulShutdown(signal));
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled promise rejection', err);
});
