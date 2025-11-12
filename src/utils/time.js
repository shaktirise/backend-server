// Utilities for consistent timestamp formatting across the API

export const APP_TIMEZONE = process.env.APP_TIMEZONE || 'Asia/Kolkata';

// Returns date parts in the configured timezone
export function getLocalDateParts(date, timeZone = APP_TIMEZONE) {
  if (!date) return null;
  const d = date instanceof Date ? date : new Date(date);
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone,
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).formatToParts(d);

  const map = Object.create(null);
  for (const p of parts) {
    if (p.type !== 'literal') map[p.type] = p.value;
  }
  return map;
}

// Formats a date into YYYY-MM-DDTHH:mm:ss in the configured timezone
export function formatLocalISO(date, timeZone = APP_TIMEZONE) {
  const p = getLocalDateParts(date, timeZone);
  if (!p) return null;
  return `${p.year}-${p.month}-${p.day}T${p.hour}:${p.minute}:${p.second}`;
}

// Numeric epoch milliseconds helper
export function toEpochMs(date) {
  return date ? (date instanceof Date ? date.getTime() : new Date(date).getTime()) : null;
}

