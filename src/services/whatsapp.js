import axios from 'axios';

// WhatsApp sender with Meta Cloud API primary, Twilio fallback, and safe dry-run default.
// Enable sending by setting WHATSAPP_SEND_ENABLED=1
// Cloud API env:
//   WHATSAPP_CLOUD_TOKEN
//   WHATSAPP_CLOUD_PHONE_ID (the WABA phone number ID, not the phone number)
// Twilio fallback env (optional):
//   TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_FROM (whatsapp:+1234567890)

function toE164IndianDefault(phone) {
  if (!phone) return null;
  const raw = String(phone).replace(/\s|-/g, '');
  if (raw.startsWith('+')) return raw;
  if (/^\d{10}$/.test(raw)) return `+91${raw}`;
  if (/^\d{11,15}$/.test(raw)) return `+${raw}`;
  return null;
}

function normalizeWhatsAppAddress(phone) {
  const e164 = toE164IndianDefault(phone);
  if (!e164) return null;
  const cleaned = e164.replace(/^whatsapp:/i, '');
  return {
    cloud: cleaned.replace(/^\+/, ''), // Cloud API expects country code digits (no plus)
    twilio: `whatsapp:${cleaned}`,
  };
}

function normalizeTwilioFrom(from) {
  if (!from) return null;
  const trimmed = String(from).trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('MG')) return trimmed;
  const cleaned = trimmed.replace(/^whatsapp:/i, '');
  return `whatsapp:${cleaned}`;
}

function isWhatsAppSendEnabled() {
  const value = String(process.env.WHATSAPP_SEND_ENABLED || '').toLowerCase();
  return value === '1' || value === 'true' || value === 'yes';
}

function hasCloudConfig() {
  return Boolean(process.env.WHATSAPP_CLOUD_TOKEN && process.env.WHATSAPP_CLOUD_PHONE_ID);
}

function hasTwilioConfig() {
  return Boolean(
    process.env.TWILIO_ACCOUNT_SID
    && process.env.TWILIO_AUTH_TOKEN
    && (process.env.TWILIO_WHATSAPP_FROM || process.env.WHATSAPP_FROM || process.env.TWILIO_FROM_WHATSAPP)
  );
}

async function sendViaCloud({ to, body }) {
  const token = process.env.WHATSAPP_CLOUD_TOKEN;
  const phoneId = process.env.WHATSAPP_CLOUD_PHONE_ID;
  const url = `https://graph.facebook.com/v20.0/${phoneId}/messages`;

  const payload = {
    messaging_product: 'whatsapp',
    to,
    type: 'text',
    text: { body },
  };

  const res = await axios.post(url, payload, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    timeout: 10000,
  });

  const msgId = res?.data?.messages?.[0]?.id;
  console.log(`[WhatsApp:Cloud] Sent to ${to}. id=${msgId || 'n/a'}`);
  return { ok: true, id: msgId || null, provider: 'cloud' };
}

async function sendViaTwilio({ to, body }) {
  const sid = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  const fromAddr = normalizeTwilioFrom(
    process.env.TWILIO_WHATSAPP_FROM || process.env.WHATSAPP_FROM || process.env.TWILIO_FROM_WHATSAPP
  );

  if (!sid || !token || !fromAddr) {
    return { ok: false, error: 'twilio_not_configured' };
  }

  const twilio = (await import('twilio')).default;
  const client = twilio(sid, token);
  const msg = await client.messages.create({ from: fromAddr, to, body });
  console.log(`[WhatsApp:Twilio] Sent to ${to}. SID=${msg.sid}`);
  return { ok: true, sid: msg.sid, provider: 'twilio' };
}

export async function sendWhatsAppText({ to, body, dryRun = false }) {
  const normalized = normalizeWhatsAppAddress(to);
  if (!normalized) {
    console.warn('[WhatsApp] Invalid phone', to);
    return { ok: false, error: 'invalid_phone' };
  }

  const enabled = isWhatsAppSendEnabled() && !dryRun;

  if (!enabled) {
    console.log(`[WhatsApp:DRYRUN] to=${normalized.cloud} body=${JSON.stringify(body)}`);
    return { ok: true, simulated: true, to: normalized.cloud, body };
  }

  try {
    if (hasCloudConfig()) {
      return await sendViaCloud({ to: normalized.cloud, body });
    }
    if (hasTwilioConfig()) {
      return await sendViaTwilio({ to: normalized.twilio, body });
    }
    console.log(`[WhatsApp:DEV] Would send to=${normalized.cloud} body=${JSON.stringify(body)} (no provider configured)`);
    return { ok: true, simulated: true, to: normalized.cloud, body };
  } catch (err) {
    console.error('[WhatsApp] Failed to send message:', err.message || err);
    return { ok: false, error: err.message || 'send_failed' };
  }
}

export function buildWelcomeMessage({ name } = {}) {
  const friendlyName = name ? ` ${name}` : '';
  return `Hi${friendlyName}, welcome to Juststock! Your account is ready. Save this WhatsApp number to keep getting the latest updates.`;
}

export async function sendWelcomeWhatsApp({ to, name, dryRun = false } = {}) {
  const body = buildWelcomeMessage({ name });
  return sendWhatsAppText({ to, body, dryRun });
}

export function isWhatsAppConfigured() {
  return hasCloudConfig() || hasTwilioConfig();
}
