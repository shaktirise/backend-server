import jwt from 'jsonwebtoken';

export function auth(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    // Normalize payload to include both id and sub for compatibility
    const id = payload.id || payload.sub;
    if (!id) throw new Error('missing subject');
    req.user = {
      id, // legacy shape
      sub: payload.sub || id,
      phone: payload.phone,
      role: payload.role,
    };
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

export function admin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  next();
}
