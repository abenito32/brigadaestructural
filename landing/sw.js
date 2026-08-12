/* Desactivador del service worker viejo.
 *
 * Hasta ahora la aplicación vivía en la raíz, así que los teléfonos que la
 * abrieron tienen un service worker registrado con alcance "/" que intercepta
 * TODA la navegación del dominio. Sin esto, esos equipos verían la aplicación
 * cacheada en vez de esta página, para siempre y sin forma de arreglarlo a
 * distancia.
 *
 * Este archivo se sirve en /sw.js solo para que ese registro viejo se actualice
 * a esta versión, borre sus cachés y se dé de baja a sí mismo. El service worker
 * de la aplicación es otro y vive en /app/sw.js, con alcance /app/.
 *
 * No borrar este archivo aunque parezca inútil: mientras exista un teléfono con
 * el registro viejo, es lo único que lo libera.
 */
self.addEventListener("install", () => self.skipWaiting());

self.addEventListener("activate", event => {
  event.waitUntil((async () => {
    const nombres = await caches.keys();
    await Promise.all(nombres.map(n => caches.delete(n)));
    await self.registration.unregister();
    // Recargar las pestañas abiertas para que salgan del control de este worker.
    const clientes = await self.clients.matchAll({ type: "window" });
    clientes.forEach(c => c.navigate(c.url));
  })());
});
