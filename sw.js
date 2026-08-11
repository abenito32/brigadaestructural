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

const CACHE = "brigada-v8";   // subir en CADA cambio de los archivos cacheados
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
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;

  // El panel y la API nunca pasan por caché. Dos razones distintas y ambas serias:
  // una respuesta de error cacheada queda pegada para siempre (un 404 de /admin
  // sobrevive a configurar la clave en el servidor), y el panel muestra
  // direcciones y coordenadas, que no pueden quedar guardadas en el disco del
  // navegador (Ley 1581 de 2012).
  if (url.pathname.startsWith("/admin") || url.pathname.startsWith("/api")) return;

  e.respondWith(
    caches.match(req).then(hit => hit || fetch(req).then(res => {
      // Solo se cachea lo que salió bien. Guardar un 404 o un 500 es convertir
      // un problema pasajero del servidor en uno permanente del teléfono.
      if (res.ok && res.type === "basic") {
        const copia = res.clone();
        caches.open(CACHE).then(c => c.put(req, copia));
      }
      return res;
    }).catch(() => caches.match("./index.html")))
  );
});
