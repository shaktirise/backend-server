import crypto from 'crypto';

function requiredEnv(name) {
  const value = process.env[name];
  if (!value || !String(value).trim()) return null;
  return String(value).trim();
}

export function isCloudinaryConfigured() {
  return !!(
    requiredEnv('CLOUDINARY_CLOUD_NAME') &&
    requiredEnv('CLOUDINARY_API_KEY') &&
    requiredEnv('CLOUDINARY_API_SECRET')
  );
}

function buildSignature(params, apiSecret) {
  const toSign = Object.keys(params)
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join('&') + apiSecret;
  return crypto.createHash('sha1').update(toSign).digest('hex');
}

function coerceToDataUri(input, mime) {
  if (typeof input !== 'string' || !input) return null;
  const s = input.trim();
  if (s.startsWith('data:')) return s; 
  if (/^https?:\/\//i.test(s)) return s; 
  const m = typeof mime === 'string' && mime.trim() ? mime.trim() : 'image/png';
  return `data:${m};base64,${s}`;
}

export async function uploadImage({ file, folder, publicId, mimeType } = {}) {
  const cloudName = requiredEnv('CLOUDINARY_CLOUD_NAME');
  const apiKey = requiredEnv('CLOUDINARY_API_KEY');
  const apiSecret = requiredEnv('CLOUDINARY_API_SECRET');
  const defaultFolder = requiredEnv('CLOUDINARY_IMAGE_FOLDER') || 'juststock-image';

  if (!cloudName || !apiKey || !apiSecret) {
    throw new Error('cloudinary_not_configured');
  }

  const fileParam = coerceToDataUri(file, mimeType);
  if (!fileParam) throw new Error('invalid_file');

  const effectiveFolder = folder || defaultFolder;
  const timestamp = Math.floor(Date.now() / 1000);
  const signParams = { folder: effectiveFolder, timestamp };
  if (publicId) signParams.public_id = publicId;
  const signature = buildSignature(signParams, apiSecret);

  const form = new FormData();
  form.append('file', fileParam);
  form.append('api_key', apiKey);
  form.append('timestamp', String(timestamp));
  form.append('signature', signature);
  form.append('folder', effectiveFolder);
  if (publicId) form.append('public_id', publicId);

  const res = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/image/upload`, {
    method: 'POST',
    body: form,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`cloudinary_upload_failed:${res.status}:${text}`);
  }

  const data = await res.json();
  return {
    url: data.secure_url || data.url,
    publicId: data.public_id,
    width: data.width,
    height: data.height,
    bytes: data.bytes,
    format: data.format,
    folder: data.folder,
  };
}

