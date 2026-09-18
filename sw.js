// Bump this on every change to this file (or to what should be precached) --
// it's the only thing that makes an already-installed browser notice there's
// a new service worker at all. Without a byte-level change here, browsers
// never re-run install/activate, no matter how often index.html changes.
const CACHE = 'cissp-v2';
const ASSETS = ['/index.html', '/manifest.json', '/icon.svg'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  if (e.request.url.includes('supabase.co')) return;

  const isHTML = e.request.destination === 'document'
    || e.request.url.endsWith('/')
    || e.request.url.endsWith('.html');

  if (isHTML) {
    // Network-first: always fetch fresh HTML, fall back to cache when offline.
    // cache: 'no-store' bypasses the browser's own HTTP cache so this is a
    // real round-trip every time, not just a promise that reads like one.
    e.respondWith(
      fetch(e.request, { cache: 'no-store' })
        .then(r => {
          const clone = r.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
          return r;
        })
        .catch(() => caches.match(e.request))
    );
    return;
  }

  // Cache-first for static assets (icon, manifest)
  e.respondWith(
    caches.match(e.request).then(r => r || fetch(e.request))
  );
});
