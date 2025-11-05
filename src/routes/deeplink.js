import express from 'express';
import crypto from 'crypto';

const router = express.Router();

function base64urlEncode(jsonString) {
  return Buffer.from(jsonString)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64urlDecode(b64url) {
  const pad = b64url.length % 4 === 0 ? '' : '='.repeat(4 - (b64url.length % 4));
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/') + pad;
  return Buffer.from(b64, 'base64').toString('utf8');
}

function sign(code, secret) {
  return crypto.createHmac('sha256', secret).update(code).digest('hex').slice(0, 16);
}

function getSecret() {
  return process.env.DEEPLINK_SECRET || process.env.JWT_SECRET || 'juststock-demo-secret';
}

function getBaseUrl(req) {
  const fromEnv = process.env.PUBLIC_BASE_URL || process.env.BASE_URL;
  if (fromEnv) return fromEnv.replace(/\/?$/, '');
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').toString();
  const host = req.get('host');
  return `${proto}://${host}`;
}

function getStoreUrls() {
  // Only use explicit links; do not auto-compose Play link
  const play = process.env.PLAY_STORE_URL || '';
  const appStoreUrl = process.env.APP_STORE_URL || '';
  const apk = process.env.APK_DOWNLOAD_URL || 'https://juststock.in/assets/app/base.apk';
  return { play, appStoreUrl, apk };
}

function getAppSchemeUrl(code) {
  const scheme = (process.env.APP_CUSTOM_SCHEME || 'juststock').replace(/:\/\/$/, '');
  // Use host 'referral' to match juststock://referral?code=...
  return `${scheme}://referral?code=${encodeURIComponent(code)}`;
}

function isAndroid(ua = '') {
  return /Android/i.test(ua);
}

function isIOS(ua = '') {
  return /iPhone|iPad|iPod/i.test(ua);
}

function buildOgMeta({ title, description, image, url }) {
  return `
    <meta property="og:type" content="website" />
    <meta property="og:title" content="${escapeHtml(title || 'Open in App')}" />
    <meta property="og:description" content="${escapeHtml(description || '')}" />
    ${image ? `<meta property="og:image" content="${escapeHtml(image)}" />` : ''}
    ${url ? `<meta property="og:url" content="${escapeHtml(url)}" />` : ''}
  `;
}

function escapeHtml(str = '') {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function verifyAndDecode(code) {
  const [b64, sig] = String(code || '').split('.');
  if (!b64 || !sig) return { ok: false, error: 'invalid_code' };
  const secret = getSecret();
  const expect = sign(b64, secret);
  if (expect !== sig) return { ok: false, error: 'bad_signature' };
  try {
    const json = base64urlDecode(b64);
    const payload = JSON.parse(json);
    return { ok: true, payload };
  } catch (e) {
    return { ok: false, error: 'bad_payload' };
  }
}

// Create a signed share link code and URL
router.post('/api/deeplink/create', (req, res) => {
  try {
    const providedKey = req.headers['x-api-key'] || req.query.key || req.body?.key;
    const expectedKey = process.env.DEEPLINK_API_KEY || 'JS_DEEPLINK_KEY_2025';
    if (!providedKey || providedKey !== expectedKey) {
      return res.status(401).json({ error: 'unauthorized', message: 'invalid_api_key' });
    }
    const { type, id, title, description, image, webUrl, extra } = req.body || {};
    if (!type || !id) return res.status(400).json({ error: 'type_and_id_required' });

    const defaults = {};
    if (type === 'referral') {
      defaults.title = 'JustStock Referral';
      defaults.description = 'Install and open to auto-apply my referral';
      defaults.webUrl = `https://juststock.in/invite?ref=${encodeURIComponent(id)}`;
    }

    const payload = {
      type,
      id,
      title: title || defaults.title,
      description: description || defaults.description,
      image: image || undefined,
      webUrl: webUrl || defaults.webUrl,
      extra: extra || undefined,
      ts: Date.now(),
    };

    const json = JSON.stringify(payload);
    const b64 = base64urlEncode(json);
    const code = `${b64}.${sign(b64, getSecret())}`;
    const base = getBaseUrl(req);
    const shareUrl = `${base}/d/${code}`;
    const appUrl = getAppSchemeUrl(code);
    const appUrlRaw = type === 'referral' ? `juststock://referral?code=${encodeURIComponent(id)}` : undefined;

    return res.json({ code, shareUrl, appUrl, appUrlRaw, payload, signed: true });
  } catch (e) {
    return res.status(500).json({ error: 'create_failed' });
  }
});

// Simpler: create a referral deep link without signing, using the raw code directly.
// Protected by the same API key for basic abuse prevention.
router.get('/api/deeplink/referral/:refCode', (req, res) => {
  const providedKey = req.headers['x-api-key'] || req.query.key;
  const expectedKey = process.env.DEEPLINK_API_KEY || 'JS_DEEPLINK_KEY_2025';
  if (!providedKey || providedKey !== expectedKey) {
    return res.status(401).json({ error: 'unauthorized', message: 'invalid_api_key' });
  }
  const id = req.params.refCode;
  const base = getBaseUrl(req);
  const code = id; // plain referral code
  const shareUrl = `${base}/d/${encodeURIComponent(code)}`;
  const appUrl = getAppSchemeUrl(code); // juststock://referral?code=...
  const payload = {
    type: 'referral',
    id,
    title: 'JustStock Referral',
    description: 'Install and open to auto-apply my referral',
    webUrl: `https://juststock.in/invite?ref=${encodeURIComponent(id)}`,
    ts: Date.now(),
  };
  return res.json({ code, shareUrl, appUrl, payload, signed: false });
});

// Resolve a code to JSON payload (Flutter app can call this)
router.get('/api/deeplink/resolve/:code', (req, res) => {
  const { code } = req.params;
  const result = verifyAndDecode(code);
  const payload = result.ok ? result.payload : { type: 'referral', id: code };
  return res.json({ code, payload, verified: !!result.ok });
});

// Redirect/HTML landing that attempts to open the app, with store fallback.
router.get('/d/:code', (req, res) => {
  const { code } = req.params;
  const ua = req.headers['user-agent'] || '';
  const base = getBaseUrl(req);
  const result = verifyAndDecode(code);

  const { play, appStoreUrl, apk } = getStoreUrls();
  const androidFallback = apk || play || base;
  const androidLabel = apk ? 'Download APK' : 'Get on Play Store';
  const iosFallback = appStoreUrl || base;
  const appUrl = getAppSchemeUrl(code);

  const payload = result.ok ? result.payload : { type: 'referral', id: code };
  const title = payload.title || process.env.APP_NAME || 'JustStock';
  const description = payload.description || 'Tap to continue in the app';
  const image = payload.image || '';
  const ogUrl = `${base}/d/${encodeURIComponent(code)}`;

  const preferredFallback = isIOS(ua) ? iosFallback : isAndroid(ua) ? androidFallback : base;

  const html = `<!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    ${buildOgMeta({ title, description, image, url: ogUrl })}
    <meta name="apple-itunes-app" content="app-argument=${escapeHtml(appUrl)}" />
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 0; padding: 24px; background: #0b0f17; color: #fff; }
      .card { max-width: 640px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 24px; }
      .title { font-size: 22px; font-weight: 600; margin: 0 0 8px; }
      .desc { color: #9ca3af; margin: 0 0 16px; }
      .btns { display: flex; gap: 12px; }
      .btn { display: inline-block; padding: 12px 16px; border-radius: 10px; text-decoration: none; color: #fff; font-weight: 600; }
      .primary { background: #2563eb; }
      .secondary { background: #374151; }
      img.preview { max-width: 100%; border-radius: 10px; margin: 12px 0 16px; border: 1px solid #1f2937; }
    </style>
    <script>
      (function(){
        var appUrl = ${JSON.stringify(appUrl)};
        var fallback = ${JSON.stringify(preferredFallback)};
        var isIOS = /iPhone|iPad|iPod/i.test(navigator.userAgent);
        var isAndroid = /Android/i.test(navigator.userAgent);
        // Try to open the app via custom scheme
        function openApp(){
          var start = Date.now();
          var timeout = setTimeout(function(){
            var elapsed = Date.now() - start;
            if (elapsed < 1800) { window.location.href = fallback; }
          }, 1200);
          window.location.href = appUrl;
        }
        window.addEventListener('load', function(){
          openApp();
        });
      })();
    </script>
  </head>
  <body>
    <div class="card">
      <div class="title">${escapeHtml(title)}</div>
      <p class="desc">${escapeHtml(description)}</p>
      ${image ? `<img class="preview" src="${escapeHtml(image)}" alt="" />` : ''}
      <div class="btns">
        <a class="btn primary" href="${escapeHtml(appUrl)}">Open in App</a>
        ${isIOS(ua) && iosFallback ? `<a class="btn secondary" href="${escapeHtml(iosFallback)}">Get on App Store</a>` : ''}
        ${isAndroid(ua) && androidFallback ? `<a class="btn secondary" href="${escapeHtml(androidFallback)}">${escapeHtml(androidLabel)}</a>` : ''}
      </div>
    </div>
  </body>
  </html>`;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.status(200).send(html);
});

// Android App Links association
router.get('/.well-known/assetlinks.json', (req, res) => {
  const pkg = process.env.ANDROID_PACKAGE_NAME;
  const digests = (process.env.ANDROID_SHA256_DIGESTS || '')
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
  if (!pkg || !digests.length) return res.status(404).json({ error: 'not_configured' });
  const body = [
    {
      relation: ['delegate_permission/common.handle_all_urls'],
      target: { namespace: 'android_app', package_name: pkg, sha256_cert_fingerprints: digests },
    },
  ];
  res.setHeader('Content-Type', 'application/json');
  return res.send(JSON.stringify(body));
});

// iOS Universal Links association
router.get('/.well-known/apple-app-site-association', (req, res) => {
  const appID = process.env.IOS_APP_ID; // TeamID.BundleID
  if (!appID) return res.status(404).json({ error: 'not_configured' });
  const details = [
    {
      appID,
      paths: ['/d/*'],
    },
  ];
  const body = { applinks: { apps: [], details } };
  res.setHeader('Content-Type', 'application/json');
  return res.send(JSON.stringify(body));
});

export default router;
