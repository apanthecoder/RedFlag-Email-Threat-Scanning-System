/** Parse a timestamp from the backend.
 *
 * The backend stores UTC times as "YYYY-MM-DD HH:MM:SS.ffffff" with no
 * time zone. Given that string, most browsers assume local time, which in
 * Malaysia puts every time eight hours early, and some browsers can't
 * read it at all. So convert it to ISO 8601 in UTC first.
 *
 * Returns a Date, or null if the value can't be read.
 */
export function parseServerTime(value) {
  if (!value) return null;
  const iso = String(value)
    .trim()
    .replace(" ", "T")
    .replace(/(\.\d{3})\d+/, "$1"); // keep milliseconds, drop microseconds
  const hasZone = /(Z|[+-]\d{2}:?\d{2})$/i.test(iso);
  const date = new Date(hasZone ? iso : `${iso}Z`);
  return Number.isNaN(date.getTime()) ? null : date;
}
