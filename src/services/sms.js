// Minimal SMS sender with Twilio support and safe fallback.
// Configure via env:
// - TWILIO_ACCOUNT_SID
// - TWILIO_AUTH_TOKEN
// - TWILIO_FROM (Twilio phone number or Messaging Service SID)

function toE164(phone) {
  if (!phone) return null;
  const raw = String(phone).replace(/\s|-/g, '');
  if (raw.startsWith('+')) return raw;
  if (/^\d{10}$/.test(raw)) return `+91${raw}`;
  if (/^\d{11,15}$/.test(raw)) return `+${raw}`;
  return null;
}

export async function sendOtpSms(phone, code) {
  const to = toE164(phone);
  if (!to) {
    console.warn(`[SMS] Invalid phone: ${phone}`);
    return false;
  }

  const sid = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  const from = process.env.TWILIO_FROM;
  if (!sid || !token || !from) {
    console.log(`[SMS:DEV] Would send OTP ${code} to ${to}. Configure Twilio env to enable sending.`);
    return false;
  }

  try {
    const twilio = (await import('twilio')).default;
    const client = twilio(sid, token);
    const params = from.startsWith('MG')
      ? { messagingServiceSid: from, to, body: `Your verification code is ${code}` }
      : { from, to, body: `Your verification code is ${code}` };
    const msg = await client.messages.create(params);
    console.log(`[SMS] Sent OTP to ${to}. SID=${msg.sid}`);
    return true;
  } catch (e) {
    console.error('[SMS] Failed to send OTP via Twilio:', e.message || e);
    return false;
  }
}

function isSmsSendingEnabled() {
  const v = String(process.env.SMS_SEND_ENABLED || '').toLowerCase();
  return v === 'true' || v === '1' || v === 'yes';
}

export async function sendTextSms(phone, body, opts = {}) {
  const to = toE164(phone);
  if (!to) {
    console.warn(`[SMS] Invalid phone: ${phone}`);
    return { ok: false, error: 'invalid_phone' };
  }

  const sid = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  const from = process.env.TWILIO_FROM;
  const dryRun = opts.dryRun === true || !isSmsSendingEnabled();

  if (dryRun) {
    console.log(`[SMS:DRYRUN] to=${to} body=${JSON.stringify(body)}`);
    return { ok: true, simulated: true, to, body };
  }

  if (!sid || !token || !from) {
    console.log(`[SMS:DEV] Would send to ${to}: ${body}. Configure Twilio env to enable sending.`);
    return { ok: false, error: 'twilio_not_configured' };
  }

  try {
    const twilio = (await import('twilio')).default;
    const client = twilio(sid, token);
    const params = from.startsWith('MG')
      ? { messagingServiceSid: from, to, body }
      : { from, to, body };
    const msg = await client.messages.create(params);
    console.log(`[SMS] Sent to ${to}. SID=${msg.sid}`);
    return { ok: true, sid: msg.sid };
  } catch (e) {
    console.error('[SMS] Failed to send via Twilio:', e.message || e);
    return { ok: false, error: e.message || 'send_failed' };
  }
}
