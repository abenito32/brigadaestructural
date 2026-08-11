const CACHE = "brigada-v1";
const ARCHIVOS = ["./", "./index.html", "./manifest.json"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ARCHIVOS)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", e => {
  e.waitUntil(
    caches.keys()
      .then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// Cache-first para el armazón; la red nunca bloquea el uso en campo.
self.addEventListener("fetch", e => {
  const req = e.request;
  if (req.method !== "GET") return;               // el POST de sincronización pasa directo
  if (new URL(req.url).origin !== location.origin) return;
  e.respondWith(
    caches.match(req).then(hit => hit || fetch(req).then(res => {
      const copia = res.clone();
      caches.open(CACHE).then(c => c.put(req, copia));
      return res;
    }).catch(() => caches.match("./index.html")))
  );
});
