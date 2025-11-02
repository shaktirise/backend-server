import express from 'express';
import SegmentMessage, { SEGMENT_KEYS, normalizeSegmentKey } from '../models/SegmentMessage.js';
import SegmentMessageHistory from '../models/SegmentMessageHistory.js';
import { auth, admin } from '../middleware/auth.js';
import { isCloudinaryConfigured, uploadImage } from '../services/cloudinary.js';

const router = express.Router();

const SEGMENT_METADATA = {
   STOCKS: { label: 'Stocks' },
  FUTURE: { label: 'Future' },
  OPTIONS: { label: 'Options' },
  COMMODITY: { label: 'Commodity' },
};

function serializeSegment(doc, fallbackKey) {
  if (!doc) {
    return {
      key: fallbackKey,
      label: SEGMENT_METADATA[fallbackKey]?.label || fallbackKey,
      message: '',
      imageUrl: '',
      updatedAt: null,
      updatedBy: null,
    };
  }

  return {
    key: doc.segment,
    label: SEGMENT_METADATA[doc.segment]?.label || doc.segment,
    message: doc.message || '',
    imageUrl: doc.imageUrl || '',
    updatedAt: doc.updatedAt || null,
    updatedBy: doc.updatedBy ? String(doc.updatedBy) : null,
  };
}

router.get('/', async (req, res) => {
  try {
    const messages = await SegmentMessage.find({ segment: { $in: SEGMENT_KEYS } }).lean();
    const messageMap = new Map(messages.map((item) => [item.segment, item]));
    const segments = SEGMENT_KEYS.map((key) => serializeSegment(messageMap.get(key), key));
    return res.json({ segments });
  } catch (err) {
    console.error('Failed to fetch segment messages', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/:segment/history', async (req, res) => {
  try {
    const key = normalizeSegmentKey(req.params.segment);
    if (!key) return res.status(404).json({ error: 'segment not found' });

    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
    const history = await SegmentMessageHistory.find({ segment: key })
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();

    return res.json({
      segment: key,
      entries: history.map((entry) => ({
        id: entry._id,
        message: entry.message,
        updatedBy: entry.updatedBy ? String(entry.updatedBy) : null,
        createdAt: entry.createdAt,
      })),
    });
  } catch (err) {
    console.error('Failed to fetch segment history', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/:segment', async (req, res) => {
  try {
    const key = normalizeSegmentKey(req.params.segment);
    if (!key) return res.status(404).json({ error: 'segment not found' });
    const message = await SegmentMessage.findOne({ segment: key }).lean();
    return res.json(serializeSegment(message, key));
  } catch (err) {
    console.error('Failed to fetch segment message', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/:segment', auth, admin, async (req, res) => {
  try {
    const key = normalizeSegmentKey(req.params.segment);
    if (!key) return res.status(404).json({ error: 'segment not found' });

    const { message, imageBase64, imageDataUrl, imageUrl, imageMimeType } = req.body || {};
    if (typeof message !== 'string' || !message.trim()) {
      return res.status(400).json({ error: 'message required' });
    }

    const trimmed = message.trim();
    if (trimmed.length > 1000) {
      return res.status(400).json({ error: 'message too long (max 1000 chars)' });
    }

    let uploaded = null;
    const anyImage = imageDataUrl || imageBase64 || imageUrl;
    if (anyImage) {
      if (!isCloudinaryConfigured()) {
        return res.status(500).json({ error: 'cloudinary not configured' });
      }
      try {
        const file = imageDataUrl || imageUrl || imageBase64; 
        uploaded = await uploadImage({ file, mimeType: imageMimeType });
      } catch (e) {
        console.error('Cloudinary upload failed', e);
        return res.status(502).json({ error: 'image upload failed' });
      }
    }

    const updateDoc = { segment: key, message: trimmed, updatedBy: req.user?.id || null };
    if (uploaded) {
      updateDoc.imageUrl = uploaded.url || '';
      updateDoc.imagePublicId = uploaded.publicId || '';
    }

    const updated = await SegmentMessage.findOneAndUpdate(
      { segment: key },
      updateDoc,
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    await SegmentMessageHistory.create({
      segment: key,
      message: trimmed,
      updatedBy: req.user?.id || null,
    });

    const response = serializeSegment(updated);

    const io = req.app.get('io');
    if (io) {
      io.emit('segment:update', {
        segment: response.key,
        message: response.message,
        updatedAt: response.updatedAt,
      });
    }

    return res.json(response);
  } catch (err) {
    console.error('Failed to upsert segment message', err);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;
