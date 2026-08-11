/* Brigada · Evaluación estructural en campo
   Copyright (C) 2026 Rollout Comercio e Servicios Limitada / Andrés Benito Revollo Vélez
   
   Este programa es software libre: usted puede redistribuirlo y/o
   modificarlo bajo los términos de la Licencia Pública General Affero
   de GNU publicada por la Free Software Foundation, en su versión 3 o
   (a su elección) cualquier versión posterior.
   
   Se distribuye con la esperanza de que sea útil, pero SIN NINGUNA
   GARANTÍA; ni siquiera la garantía implícita de COMERCIABILIDAD o
   IDONEIDAD PARA UN PROPÓSITO PARTICULAR. Vea la Licencia para más detalle.
   
   Debería haber recibido una copia junto con este programa. Si no,
   vea <https://www.gnu.org/licenses/>.
 */

const CACHE = "brigada-v3";   // subir en CADA cambio de los archivos cacheados
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
