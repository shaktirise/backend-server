import nodemailer from 'nodemailer';

function isTruthy(v) {
  const val = String(v || '').toLowerCase();
  return val === '1' || val === 'true' || val === 'yes';
}

function buildTransport() {
  const host = process.env.SMTP_HOST;
  const portRaw = parseInt(process.env.SMTP_PORT || '0', 10);
  const port = Number.isFinite(portRaw) && portRaw > 0 ? portRaw : undefined;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!host || !port || !user || !pass) {
    return null;
  }

  const secureEnv = process.env.SMTP_SECURE;
  const secure = typeof secureEnv === 'undefined' ? port === 465 : isTruthy(secureEnv);

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },
  });
}

let transport;

function getTransport() {
  if (transport !== undefined) return transport;
  transport = buildTransport();
  return transport;
}

export async function sendEmail({ to, subject, text, html }) {
  const tx = getTransport();
  if (!tx) {
    console.log(`[Email:DEV] Would send to=${to} subject=${subject}`);
    return { ok: false, simulated: true };
  }
  try {
    const from = process.env.SMTP_FROM || process.env.SMTP_USER;
    const info = await tx.sendMail({ from, to, subject, text, html });
    console.log(`[Email] Sent message id=${info.messageId} to=${to}`);
    return { ok: true, messageId: info.messageId };
  } catch (err) {
    console.error('[Email] Send failed:', err.message || err);
    return { ok: false, error: err.message || 'send_failed' };
  }
}

export async function sendResetPasswordEmail(to, code, ttlMinutes) {
  const subject = 'Your password reset code';
  const text = [
    'You requested to reset your password.',
    '',
    `Your OTP code: ${code}`,
    `This code expires in ${ttlMinutes} minutes.`,
    '',
    'If you did not request this, you can ignore this email.',
  ].join('\n');

  return sendEmail({ to, subject, text });
}
