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

