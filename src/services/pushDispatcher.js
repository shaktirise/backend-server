import EventEmitter from 'events';
import { sendPushNotification } from './push.js';

const bus = new EventEmitter();
bus.setMaxListeners(20);

function fireAndForget(handler) {
  return (payload) =>
    setImmediate(() => {
      Promise.resolve(handler(payload)).catch((err) => {
        console.error('[PushEvents] handler error', err?.message || err);
      });
    });
}

function formatAmount(amountMinor, currency = 'INR') {
  const minor = Number.isFinite(amountMinor) ? Number(amountMinor) : 0;
  const value = currency === 'INR' ? minor / 100 : minor;
  return value.toLocaleString('en-IN', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

async function notifyUser(userId, payload) {
  if (!userId) return;
  await sendPushNotification({ userIds: [userId], ...payload });
}

bus.on(
  'wallet.deposit.captured',
  fireAndForget(async ({ userId, amount, paymentId, currency = 'INR' } = {}) => {
    const formattedAmount = formatAmount(amount, currency);
    await notifyUser(userId, {
      title: 'Payment received',
      body: `${currency} ${formattedAmount} added to your wallet.`,
      data: {
        type: 'wallet_topup',
        paymentId: paymentId ? String(paymentId) : '',
        amount: formattedAmount,
        currency,
        deeplink: 'app://wallet',
        screen: 'wallet',
      },
    });
  }),
);

bus.on(
  'admin.notification',
  fireAndForget(async ({ userIds = [], title, body, data = {} } = {}) => {
    if (!Array.isArray(userIds) || userIds.length === 0) return;
    await sendPushNotification({
      userIds,
      title: title || 'Notification',
      body: body || '',
      data: { ...data, type: data.type || 'admin_notice' },
    });
  }),
);

export function emitPushEvent(eventName, payload = {}) {
  bus.emit(eventName, payload);
}

export default bus;
