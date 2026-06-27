const CACHE = 'cissp-v1';
const ASSETS = ['/index.html', '/manifest.json', '/icon.svg'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  if (e.request.url.includes('supabase.co')) return;

  const isHTML = e.request.destination === 'document'
    || e.request.url.endsWith('/')
    || e.request.url.endsWith('.html');

  if (isHTML) {
    // Network-first: always fetch fresh HTML, fall back to cache when offline
    e.respondWith(
      fetch(e.request)
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
