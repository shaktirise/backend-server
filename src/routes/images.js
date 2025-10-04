import express from 'express';
import crypto from 'crypto';
import { auth, admin } from '../middleware/auth.js';
import Image from '../models/Image.js';

const router = express.Router();

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

function loadCloudinaryConfig() {L
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
