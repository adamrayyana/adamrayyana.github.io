const base = import.meta.env.BASE_URL.replace(/\/$/, '');

export function withBase(path = '/') {
  if (/^(https?:|mailto:|#)/.test(path)) return path;
  const normalized = path.startsWith('/') ? path : `/${path}`;
  return `${base}${normalized}` || '/';
}
