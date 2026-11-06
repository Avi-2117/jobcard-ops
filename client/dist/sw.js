const CACHE = 'jobcard-ops-v5';
const ASSETS = [
  '/',
  '/manifest.json',
  '/logo.png',
  '/icon-192.png',
  '/icon-512.png',
  '/apple-touch-icon.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Only handle this app's own files. Other sites (address search, fonts, maps)
  // go straight to the network so their responses are never cached here.
  if (url.origin !== self.location.origin) return;

  // Never cache API or HTML — always network
  if (
    url.pathname.startsWith('/api/') ||
    event.request.mode === 'navigate' ||
    url.pathname === '/' ||
    url.pathname.endsWith('.html') ||
    url.pathname.endsWith('sw.js')
  ) {
    event.respondWith(
      fetch(event.request).catch(async () => {
        if (event.request.mode === 'navigate') {
          const cachedPage = await caches.match('/');
          if (cachedPage) return cachedPage;
          return new Response('<h1>Offline</h1><p>Reconnect to continue using JobCard Ops.</p>', { headers: { 'Content-Type': 'text/html' } });
        }
        return new Response(JSON.stringify({ error: 'Offline' }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' }
        });
      })
    );
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      return fetch(event.request).then((res) => {
        if (res.ok && event.request.method === 'GET') {
          const clone = res.clone();
          caches.open(CACHE).then((cache) => cache.put(event.request, clone));
        }
        return res;
      });
    })
  );
});
