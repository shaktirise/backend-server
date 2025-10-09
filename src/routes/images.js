import express from 'express';
import crypto from 'crypto';
import { auth, admin } from '../middleware/auth.js';
import Image from '../models/Image.js';
import { uploadImage } from '../services/cloudinary.js';
import multer from 'multer';

const router = express.Router();

const MAX_UPLOAD_BYTES = (() => {
  const raw = Number.parseInt(process.env.IMAGE_UPLOAD_MAX_BYTES || '', 10);
  if (Number.isFinite(raw) && raw > 0) return raw;
  return 5 * 1024 * 1024; // 5MB default
})();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_UPLOAD_BYTES,
  },
});

const FILE_FIELD_CONFIG = [
  { name: 'files', maxCount: 5 },
  { name: 'file', maxCount: 5 },
  { name: 'images', maxCount: 5 },
  { name: 'image', maxCount: 5 },
];

const multipartUpload = upload.fields(FILE_FIELD_CONFIG);

function runMultipart(req, res, next) {
  multipartUpload(req, res, (err) => {
    if (!err) return next();

    if (err?.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({
        error: 'file_too_large',
        maxBytes: MAX_UPLOAD_BYTES,
      });
    }

    if (err?.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({
        error: 'unexpected_file_field',
        field: err.field,
      });
    }

    console.error('multer parse images error', err);
    return res.status(400).json({ error: 'invalid_multipart' });
  });
}

function flattenUploadedFiles(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw.filter(Boolean);
  if (typeof raw === 'object') {
    return Object.values(raw)
      .flat()
      .filter(Boolean);
  }
  return [];
}

function coerceBodyItems(value) {
  const out = [];
  const visit = (item) => {
    if (item === undefined || item === null) return;
    if (Array.isArray(item)) {
      item.forEach(visit);
      return;
    }
    if (typeof item === 'string') {
      const trimmed = item.trim();
      if (!trimmed) return;
      if (
        (trimmed.startsWith('[') && trimmed.endsWith(']')) ||
        (trimmed.startsWith('{') && trimmed.endsWith('}'))
      ) {
        try {
          const parsed = JSON.parse(trimmed);
          visit(parsed);
          return;
        } catch (e) {
          // fall back to treating the value as a plain string
        }
      }
      out.push(trimmed);
      return;
    }
    if (typeof item === 'object') {
      out.push(item);
      return;
    }
    out.push(String(item));
  };

  visit(value);
  return out;
}

function parseCloudinaryUrl(url) {
  try {
    const u = new URL(url);

    const apiKey = u.username;
    const apiSecret = u.password;
    const cloudName = u.hostname;
    if (apiKey && apiSecret && cloudName) return { apiKey, apiSecret, cloudName };
    return null;
  } catch {
    return null;
  }
}

function loadCloudinaryConfig() {
  const explicit = {
    cloudName: process.env.CLOUDINARY_CLOUD_NAME,
    apiKey: process.env.CLOUDINARY_API_KEY,
    apiSecret: process.env.CLOUDINARY_API_SECRET,
  };
  if (explicit.cloudName && explicit.apiKey && explicit.apiSecret) return explicit;

  const parsed = process.env.CLOUDINARY_URL ? parseCloudinaryUrl(process.env.CLOUDINARY_URL) : null;
  if (parsed) return parsed;

  throw new Error('Missing Cloudinary configuration. Set CLOUDINARY_URL or CLOUDINARY_CLOUD_NAME/API_KEY/API_SECRET');
}

function createCloudinarySignature(params, apiSecret) {
  const keys = Object.keys(params)
    .filter((k) => params[k] !== undefined && params[k] !== null && params[k] !== '')
    .sort();
  const toSign = keys.map((k) => `${k}=${params[k]}`).join('&');
  const hash = crypto.createHash('sha1').update(`${toSign}${apiSecret}`).digest('hex');
  return hash;
}

router.post('/signature', auth, admin, (req, res) => {
  try {
    const { cloudName, apiKey, apiSecret } = loadCloudinaryConfig();

    const folder = req.body?.folder || process.env.CLOUDINARY_UPLOAD_FOLDER || undefined;
    const tagsArr = Array.isArray(req.body?.tags) ? req.body.tags : undefined;
    const tags = tagsArr && tagsArr.length ? tagsArr.join(',') : undefined;
    const timestamp = Math.floor(Date.now() / 1000);

    const signature = createCloudinarySignature({ timestamp, folder, tags }, apiSecret);

    return res.json({
      cloudName,
      apiKey,
      timestamp,
      signature,
      folder,
      tags: tagsArr || [],
      uploadUrl: `https://api.cloudinary.com/v1_1/${cloudName}/image/upload`,
    });
  } catch (err) {
    console.error('signature error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/upload', auth, admin, runMultipart, async (req, res) => {
  try {
    const normalizedInputs = [];

    const uploadedFiles = flattenUploadedFiles(req.files);
    if (req.file) uploadedFiles.push(req.file);

    if (uploadedFiles.length) {
      for (const file of uploadedFiles) {
        const buffer = file?.buffer;
        if (!buffer || !buffer.length) continue;
        const mime = file.mimetype || 'application/octet-stream';
        const base64 = buffer.toString('base64');
        normalizedInputs.push({ file: `data:${mime};base64,${base64}` });
      }
    }

    const bodyKeys = ['files', 'file', 'images', 'image'];
    const bodyPayload = bodyKeys.reduce((acc, key) => {
      if (req.body?.[key] === undefined) return acc;
      acc.push(...coerceBodyItems(req.body[key]));
      return acc;
    }, []);

    for (const input of bodyPayload) {
      if (input === undefined || input === null) continue;
      if (typeof input === 'string') {
        normalizedInputs.push({ file: input });
      } else if (typeof input === 'object' && !Array.isArray(input)) {
        normalizedInputs.push(input);
      } else {
        return res.status(400).json({ error: 'invalid file payload' });
      }
    }

    if (!normalizedInputs.length) {
      return res.status(400).json({
        error: 'files required',
        hint: 'Send multipart/form-data with field "files" (one per image) or JSON body with base64 strings.',
      });
    }
    if (normalizedInputs.length > 10) {
      return res.status(400).json({ error: 'too_many_files', max: 10 });
    }

    const uploads = [];
    for (const itemRaw of normalizedInputs) {
      const item = itemRaw && typeof itemRaw === 'object' ? itemRaw : { file: itemRaw };
      const fileContent = typeof item.file === 'string'
        ? item.file
        : typeof item.data === 'string'
          ? item.data
          : typeof item.image === 'string'
            ? item.image
            : null;
      if (!fileContent || !fileContent.trim()) {
        return res.status(400).json({ error: 'file content required' });
      }

      let uploaded;
      try {
        uploaded = await uploadImage({
          file: fileContent,
          folder: item.folder,
          publicId: item.publicId,
          mimeType: item.mimeType,
        });
      } catch (err) {
        const message = err?.message || '';
        if (message.includes('cloudinary_not_configured')) {
          return res.status(503).json({ error: 'cloudinary_not_configured' });
        }
        console.error('cloudinary upload error', err);
        return res.status(502).json({ error: 'upload_failed' });
      }

      const tags = Array.isArray(item.tags) ? item.tags : [];
      uploads.push({
        api: uploaded,
        tags,
      });
    }

    if (!uploads.length) {
      return res.status(400).json({ error: 'no valid files' });
    }

    const docsPayload = uploads.map(({ api, tags }) => ({
      publicId: api.publicId,
      secureUrl: api.url,
      url: api.url,
      width: api.width,
      height: api.height,
      format: api.format,
      bytes: api.bytes,
      folder: api.folder,
      tags,
      createdBy: req.user?.id || null,
    }));

    const created = await Image.insertMany(docsPayload);

    const io = req.app.get('io');
    if (io && created.length) {
      io.emit(
        'images:new',
        created.map((d) => ({
          id: String(d._id),
          url: d.secureUrl || d.url,
          createdAt: d.createdAt,
        })),
      );
    }

    return res.status(201).json({
      ok: true,
      count: created.length,
      items: created.map((d) => ({
        id: String(d._id),
        publicId: d.publicId,
        secureUrl: d.secureUrl,
        url: d.url,
        width: d.width,
        height: d.height,
        format: d.format,
        bytes: d.bytes,
        folder: d.folder,
        tags: d.tags,
        createdAt: d.createdAt,
      })),
    });
  } catch (err) {
    console.error('admin upload images error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/batch', auth, admin, async (req, res) => {
  try {
    const items = Array.isArray(req.body?.items) ? req.body.items : null;
    if (!items || items.length === 0) return res.status(400).json({ error: 'items required' });

    const docs = items
      .map((it) => {
        const publicId = it.public_id || it.publicId;
        const secureUrl = it.secure_url || it.secureUrl;
        const url = it.url || undefined;
        const width = Number(it.width) || undefined;
        const height = Number(it.height) || undefined;
        const format = it.format || undefined;
        const bytes = Number(it.bytes) || undefined;
        const folder = it.folder || (publicId && publicId.includes('/') ? publicId.split('/').slice(0, -1).join('/') : undefined);
        if (!publicId || !secureUrl) return null;
        return {
          publicId,
          secureUrl,
          url,
          width,
          height,
          format,
          bytes,
          folder,
          tags: Array.isArray(it.tags) ? it.tags : [],
          createdBy: req.user?.id || null,
        };
      })
      .filter(Boolean);

    if (!docs.length) return res.status(400).json({ error: 'no valid items' });

    const created = await Image.insertMany(docs);

    const io = req.app.get('io');
    if (io && created.length) {
      io.emit('images:new', created.map((d) => ({ id: String(d._id), url: d.secureUrl, createdAt: d.createdAt })));
    }

    return res.json({ ok: true, count: created.length, items: created.map((d) => ({
      id: String(d._id),
      publicId: d.publicId,
      secureUrl: d.secureUrl,
      url: d.url,
      width: d.width,
      height: d.height,
      format: d.format,
      folder: d.folder,
      bytes: d.bytes,
      tags: d.tags,
      createdAt: d.createdAt,
    })) });
  } catch (err) {
    console.error('batch save images error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/', async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
    const images = await Image.find({}).sort({ createdAt: -1 }).limit(limit).lean();
    return res.json({
      items: images.map((d) => ({
        id: String(d._id),
        url: d.secureUrl || d.url,
        width: d.width || null,
        height: d.height || null,
        format: d.format || null,
        folder: d.folder || null,
        createdAt: d.createdAt,
      })),
    });
  } catch (err) {
    console.error('list images error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;
