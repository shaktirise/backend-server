import { v2 as cloudinary } from 'cloudinary';

function requiredEnv(name) {
  const value = process.env[name];
  if (!value || !String(value).trim()) return null;
  return String(value).trim();
}

let cloudinaryReady = false;

function ensureCloudinary() {
  if (cloudinaryReady) return;

  const cloudName = requiredEnv('CLOUDINARY_CLOUD_NAME');
  const apiKey = requiredEnv('CLOUDINARY_API_KEY');
  const apiSecret = requiredEnv('CLOUDINARY_API_SECRET');

  if (!cloudName || !apiKey || !apiSecret) {
    throw new Error('cloudinary_not_configured');
  }

  cloudinary.config({
    cloud_name: cloudName,
    api_key: apiKey,
    api_secret: apiSecret,
  });

  cloudinaryReady = true;
}

export function isCloudinaryConfigured() {
  try {
    ensureCloudinary();
    return true;
  } catch {
    return false;
  }
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
  ensureCloudinary();

  const defaultFolder = requiredEnv('CLOUDINARY_IMAGE_FOLDER') || 'juststock-image';

  const fileParam = coerceToDataUri(file, mimeType);
  if (!fileParam) throw new Error('invalid_file');

  const effectiveFolder = folder || defaultFolder;

  try {
    const result = await cloudinary.uploader.upload(fileParam, {
      folder: effectiveFolder,
      public_id: publicId || undefined,
      resource_type: 'image',
    });

    return {
      url: result.secure_url || result.url,
      publicId: result.public_id,
      width: result.width,
      height: result.height,
      bytes: result.bytes,
      format: result.format,
      folder: result.folder,
    };
  } catch (err) {
    const status = err?.http_code || 500;
    const message = err?.message || 'cloudinary_upload_failed';
    throw new Error(`cloudinary_upload_failed:${status}:${message}`);
  }
}
