import mongoose from 'mongoose';

const DEFAULT_RANGE_DAYS = 90;

export function toObjectId(value) {
  if (!value) return null;
  if (typeof value === 'string' || typeof value === 'number') {
    const str = value.toString();
    if (mongoose.Types.ObjectId.isValid(str)) {
      return new mongoose.Types.ObjectId(str);
    }
  }
  if (value instanceof mongoose.Types.ObjectId) {
    return value;
  }
  return null;
}

export function parseDate(value) {
  if (!value) return null;
  const ts = Date.parse(value);
  if (Number.isNaN(ts)) return null;
  return new Date(ts);
}

export function parseDateRange(query = {}, options = {}) {
  const { defaultDays = DEFAULT_RANGE_DAYS, maxDays = 365 } = options;
  const now = new Date();
  let from = parseDate(query.from);
  let to = parseDate(query.to);

  if (!to) {
    to = now;
  }

  if (!from) {
    const days = Number.isFinite(defaultDays) ? defaultDays : DEFAULT_RANGE_DAYS;
    from = new Date(to.getTime() - days * 24 * 60 * 60 * 1000);
  }

  const maxRangeDays = Number.isFinite(maxDays) ? maxDays : 365;
  if (to && from) {
    const diff = (to.getTime() - from.getTime()) / (24 * 60 * 60 * 1000);
    if (diff > maxRangeDays) {
      from = new Date(to.getTime() - maxRangeDays * 24 * 60 * 60 * 1000);
    }
  }

  return { from, to };
}

export function parsePagination(query = {}) {
  const pageRaw = Number.parseInt(query.page ?? query.pageNumber ?? '1', 10);
  const pageSizeRaw = Number.parseInt(query.pageSize ?? query.limit ?? '25', 10);
  const pageSize = Number.isFinite(pageSizeRaw) ? Math.min(Math.max(pageSizeRaw, 1), 200) : 25;
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? pageRaw : 1;
  const skip = (page - 1) * pageSize;
  return { page, pageSize, limit: pageSize, skip };
}

export function ensureNumber(value) {
  return Number.isFinite(value) ? value : 0;
}

export function ensureInt(value) {
  return Number.isInteger(value) ? value : 0;
}

export function toRupees(paise) {
  const value = Number.isFinite(paise) ? paise : 0;
  return Math.round(value / 100);
}
