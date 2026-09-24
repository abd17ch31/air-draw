const CACHE = 'air-draw-v1';
const ASSETS = ['./index-touch.html', './manifest.json', './icon.svg'];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  // Network-first, cache fallback (fresh content preferred)
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request))
  );
});