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

const CACHE = "brigada-v27";   // subir en CADA cambio de los archivos cacheados
// Leaflet va en la lista para que el mapa exista aunque el teléfono ya no tenga
// señal cuando se abre. Las TESELAS no se cachean: son de otro origen, son
// miles y llenarían el disco del teléfono. Sin señal el mapa avisa y la
// evaluación se guarda igual con lo que dio el GPS.
const ARMAZON = ["./", "./index.html", "./manifest.json"];
const EXTRAS = ["./vendor/leaflet.css", "./vendor/leaflet.js", "./guia.html"];

// El armazón con addAll: si falta uno de esos tres, la app no existe y la
// instalación DEBE fallar. Los extras uno por uno y tragándose el error: si
// Leaflet no se puede guardar, se pierde el mapa —una comodidad— pero no el
// modo sin conexión, que es la razón de ser de esto. Con un solo addAll de los
// cinco, un 404 en Leaflet dejaría al teléfono sin funcionar en campo.
self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE)
    .then(c => c.addAll(ARMAZON)
      .then(() => Promise.all(EXTRAS.map(u => c.add(u).catch(() => null)))))
    .then(() => self.skipWaiting()));
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
  // Desde el módulo de despacho la segunda razón pesa todavía más: /api/ruta
  // devuelve direcciones de predios TODAVÍA NO VISITADOS. Esa lista se guarda en
  // IndexedDB con su propio vencimiento, que la borra sola; una copia en la
  // caché del navegador escaparía de ese control y sobreviviría al vencimiento.
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
