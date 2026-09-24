---
titulo: "Despliegue de open-shield en Railway"
proyecto: "open-shield"
fecha: "2026-09-25"
idioma: "es"
traducido_de: "deploy-railway.md"
---

# Despliegue de open-shield en Railway

La instalación con `docker compose` del manual de operación asume un host
propio: el proxy escucha en el puerto 80, el DNS embebido de Docker resuelve el
backend, y la dirección que abre la conexión es la del cliente. Una plataforma
gestionada rompe las tres suposiciones a la vez, y los fallos son silenciosos en
lugar de ruidosos: el conjunto arranca, sirve tráfico y no protege nada.

Este documento es el ejemplo trabajado de esa topología, sobre Railway. Los
ajustes que introduce no son específicos de Railway: los mismos cuatro aplican
detrás de Fly, Cloud Run, un balanceador de AWS o Cloudflare. Están documentados
uno a uno en `deploy/.env.example`.

---

## 1. La topología

```
internet ──► borde de Railway (TLS)
                 │
                 ├──► proxy      ──► rack-backend.railway.internal   [sin dominio público]
                 │      │
                 │      └──► engine.railway.internal:8080 ──► Postgres + Redis
                 │
                 ├──► dashboard  (dominio público propio, sesión autenticada)
                 └──► rack-frontend  (SPA estática, pública)
```

Solo la API queda detrás del filtro. La SPA son ficheros estáticos: sin
analizador sintáctico, sin base de datos, sin nada donde inyectar — y ponerla
detrás del proxy gastaría el presupuesto de límite de tasa de cada visitante en
una ráfaga de peticiones de recursos, obligando a subir el límite hasta dejar de
ser un límite. Ese equilibrio es la razón por la que el presupuesto del §4 puede
seguir siendo lo bastante estrecho como para servir de algo.

**El paso que hace esto real es quitarle el dominio público a `rack-backend`.**
Un origen que siga siendo direccionable de forma directa convierte el proxy en
decoración; todas las reglas de la cadena se sortean escribiendo la URL antigua.

Todos los servicios deben vivir en **un único proyecto de Railway**: la red
privada (`*.railway.internal`) no cruza las fronteras de un proyecto.

---

## 2. Antes de empezar

- Ejecuta `make up && make smoke` en local una vez. La imagen del proxy es la
  misma en ambas topologías, así que un error de configuración sale mucho más
  barato encontrarlo en tu máquina que en un contenedor que no llega a arrancar
  en la plataforma.
- Dos secretos, generados en local y pegados en Railway, nunca versionados:

  ```bash
  make hash-password PASSWORD='la contraseña con la que vas a entrar'
  openssl rand -hex 32     # OS_SESSION_SECRET
  ```

  `make hash-password` imprime dos formas. La escapada, con cada `$` doblado,
  existe solo porque Docker Compose interpreta `$` en un fichero `.env` como el
  inicio de una variable. **Railway no. Pega la línea rotulada "El hash real
  es", sin escapar** — doblarla allí produce un hash que no corresponde a
  ninguna contraseña y una pantalla de acceso que sencillamente nunca te deja
  entrar.

---

## 3. La red privada es solo IPv6

Un proceso que escucha en `0.0.0.0` no recibe nada de otro servicio de Railway.
Las dos aplicaciones necesitan una línea cambiada antes de que el proxy pueda
alcanzarlas.

`rack-backend`, en `Procfile`:

```
web: python manage.py migrate --noinput && gunicorn core.wsgi --bind [::]:$PORT --log-file -
```

`rack-frontend`, en `package.json`:

```json
"start": "serve -s dist -l tcp://[::]:$PORT"
```

Define `PORT` explícitamente como variable en cada uno (`8000` y `3000` más
abajo). Sin dominio público la plataforma no siempre la inyecta, y el proxy
necesita un puerto con el que poder contar.

---

## 4. Los servicios

Créalos en este orden; la dirección privada de cada uno la necesita el
siguiente.

### 4.1 Almacenes de datos

Añade un **PostgreSQL** y un **Redis** del catálogo de Railway. Nómbralos
`postgres` y `redis`. Nada más: el motor aplica sus propias migraciones al
arrancar.

### 4.2 `engine`

Desde el repositorio `open-shield`. Ajustes: directorio raíz `/`, ruta del
Dockerfile `engine/Dockerfile`, comprobación de salud `/readyz`, rutas
observadas `engine/**`, `internal/**`, `migrations/**`, `go.*`. **Sin dominio
público, nunca** — el motor responde veredictos sin autenticación, porque se
supone que su único llamante alcanzable es el proxy.

```
OS_POSTGRES_DSN=${{Postgres.DATABASE_URL}}
OS_REDIS_ADDR=${{Redis.REDISHOST}}:${{Redis.REDISPORT}}
OS_REDIS_PASSWORD=${{Redis.REDISPASSWORD}}
OS_ENGINE_ADDR=:8080
OS_RATELIMIT_REQUESTS=120
OS_RATELIMIT_WINDOW_S=60
OS_MAX_BODY_INSPECT_BYTES=8192
OS_AUDIT_BUFFER=4096
OS_EVENTS_CHANNEL=openshield:events
OS_LOG_LEVEL=info
```

Comprueba los nombres exactos de las referencias en la pestaña de variables del
propio almacén; cambian entre versiones de la plantilla.

Sobre `OS_RATELIMIT_REQUESTS`: 120/min es un punto de partida para una API
detrás de una SPA, no una medición. Observa el dashboard durante una semana y
fíjalo a partir de la sesión legítima más pesada que veas, con margen. Un límite
que bloquea usuarios reales acaba desactivado, y un límite desactivado no
detiene nada.

### 4.3 `dashboard`

Mismo repositorio. Directorio raíz `/`, ruta del Dockerfile
`dashboard/api/Dockerfile`, comprobación de salud `/healthz`, rutas observadas
`dashboard/**`, `internal/**`, `go.*`. Genera un dominio público con puerto
destino `8081`.

```
OS_POSTGRES_DSN=${{Postgres.DATABASE_URL}}
OS_REDIS_ADDR=${{Redis.REDISHOST}}:${{Redis.REDISPORT}}
OS_REDIS_PASSWORD=${{Redis.REDISPASSWORD}}
OS_ENGINE_URL=http://engine.railway.internal:8080
OS_DASHBOARD_ADDR=:8081
OS_ADMIN_USER=admin
OS_ADMIN_PASSWORD_HASH=<el hash bcrypt en crudo>
OS_SESSION_SECRET=<openssl rand -hex 32>
OS_SESSION_TTL_S=28800
OS_SECURE_COOKIES=true
```

`OS_SECURE_COOKIES=true` es correcto aquí y solo aquí: la plataforma sirve este
dominio sobre HTTPS. La advertencia del manual de operación se refiere a HTTP
plano, donde ese mismo ajuste hace que el acceso aparente funcionar y falle en
silencio.

El dashboard lee el registro de auditoría completo, lo que lo convierte en la
superficie más sensible del despliegue — una sola contraseña, sin segundo
factor. Si tienes algo delante capaz de autenticar antes de que la petición
llegue, ponlo ahí.

### 4.4 `rack-backend`

Desde su propio repositorio, con `PORT=8000`. Después, **Settings → Networking →
quitar el dominio público.** Saltarse esto deja toda la cadena de reglas
sorteable.

### 4.5 `rack-frontend`

Desde su propio repositorio, con `PORT=3000`. Conserva su dominio público;
`VITE_API_URL` se rellena en el §5.

### 4.6 `proxy`

Desde el repositorio `open-shield`, tercer servicio. Directorio raíz `/proxy`,
rutas observadas `proxy/**`, comprobación de salud `/__openshield/health`,
dominio público con puerto destino `80`.

```
OS_BACKEND_URL=http://rack-backend.railway.internal:8000
OS_ENGINE_URL=http://engine.railway.internal:8080
OS_SERVER_NAME=_
OS_RESOLVER_IPV6=on
OS_TRUSTED_PROXY=0.0.0.0/0 ::/0
OS_REAL_IP_HEADER=X-Envoy-External-Address
OS_FAIL_MODE=open
OS_DECIDE_TIMEOUT_MS=150
OS_MAX_BODY_INSPECT_BYTES=8192
```

Cuatro de estas concentran toda la diferencia entre topologías, y tres de ellas
fallan en silencio si están mal:

- **`OS_RESOLVER_IPV6=on`** — `*.railway.internal` publica únicamente registros
  AAAA. Dejado en `off`, cada petición devuelve 502 con "host not found in
  upstream". Esta al menos falla de forma ruidosa.
- **`OS_TRUSTED_PROXY`** — sin ella, `remote_addr` es el borde de la
  plataforma, de modo que `ipblock` y `ratelimit` asocian internet entero a una
  sola dirección. Las reglas siguen ejecutándose y siguen reportando;
  sencillamente no protegen nada.
- **`OS_REAL_IP_HEADER=X-Envoy-External-Address`** — la cabecera que el borde de
  Railway escribe con la dirección real del cliente. `X-Forwarded-For` es una
  lista a la que el cliente puede anteponer valores, así que confiar en *esa*
  desde `0.0.0.0/0` permitiría a un atacante falsificar la dirección sobre la
  que se indexa una regla `ipblock`, o provocar el bloqueo de un tercero.
- El puerto de escucha no necesita nada: la plataforma inyecta `PORT` y el
  entrypoint lo sigue.

`OS_FAIL_MODE=open` se queda abierto. Ponerlo en `closed` significa que un
reinicio del motor se lleva la API por delante.

---

## 5. Recableado

1. Copia el dominio del proxy. En `rack-frontend`, define
   `VITE_API_URL=https://<dominio-del-proxy>` y **vuelve a desplegar** — Vite lo
   incrusta en tiempo de compilación, así que sin reconstruir la SPA sigue
   llamando a la dirección antigua y el despliegue entero aparenta funcionar
   mientras sortea el filtro por completo.
2. En `rack-backend`, añade los dominios del proxy y del frontend a
   `CORS_ALLOWED_ORIGINS` y `CSRF_TRUSTED_ORIGINS`.
3. Decide sobre `SECURE_PROXY_SSL_HEADER`. El proxy reenvía `X-Forwarded-Proto`,
   relayando únicamente `http` o `https` y recurriendo a su propio esquema en
   cualquier otro caso. Eso mantiene una cabecera malformada fuera del backend,
   pero **no** vuelve el valor digno de confianza por sí solo: lo es exactamente
   cuando un borde delante la sobrescribe, que es la condición que declara
   `OS_TRUSTED_PROXY`. Detrás del borde de la plataforma, actívalo; en un VPS
   desnudo con el proxy expuesto directamente, no.

---

## 6. Verificación

El script de humo acepta ambas URL base, así que funciona contra el despliegue
sin modificarlo:

```bash
OS_ADMIN_PASSWORD='...' ./scripts/smoke.sh https://<dominio-proxy> https://<dominio-dashboard>
```

Después confirma a mano que el filtro está filtrando de verdad y —más
importante— que ve direcciones de cliente reales:

```bash
curl -i "https://<dominio-proxy>/?q=%27%20OR%201=1--"          # 403, con X-Request-ID
curl -i "https://<dominio-proxy>/?q=%3Cscript%3Ealert(1)%3C/script%3E"   # 403

for i in $(seq 1 200); do
  curl -s -o /dev/null -w "%{http_code}\n" "https://<dominio-proxy>/"
done | sort | uniq -c                                          # aparecen 429
```

En el dashboard: eventos llegando en vivo, `GET /api/v1/audit/verify`
reportando la cadena íntegra, y `dropped` en 0 en `/api/v1/status`.

**Después mira las direcciones de origen en la lista de eventos.** Si todas las
entradas muestran la misma dirección, `real_ip` no está funcionando — revisa
`OS_TRUSTED_PROXY` y `OS_REAL_IP_HEADER`. Todo lo demás se verá perfectamente
sano mientras el límite de tasa y la lista de IP están inertes, y por eso esta
comprobación vale más que los 403 de arriba.

---

## 7. Dominios propios

Apunta `api.ejemplo.com` al proxy y `app.ejemplo.com` al frontend; Railway emite
los certificados. Después define `OS_SERVER_NAME=api.ejemplo.com` en el proxy
para que deje de aceptar cualquier cabecera `Host`, y actualiza `VITE_API_URL`,
`CORS_ALLOWED_ORIGINS` y `CSRF_TRUSTED_ORIGINS` en consecuencia.

Aquí es también donde se satisface RF-04: el TLS se termina y se renueva en el
borde de la plataforma en lugar de mediante certbot dentro del contenedor. El
bloque `443` comentado de la plantilla del proxy sigue comentado — existe para
la topología de un solo VPS, que no es la de este documento.

---

## 8. Lo que este despliegue no te da

- **La denegación de servicio volumétrica** la absorbe, o no, el borde de la
  plataforma. Una inundación sigue consumiendo ancho de banda y cómputo del
  proyecto; el motor registra que bloqueó las peticiones.
- **El registro de auditoría no se puede podar.** Ahora vive en un Postgres
  gestionado y crece sin techo. Borrar filas rompe la cadena exactamente igual
  que lo haría un atacante. Presupuéstalo.
- **El tráfico dentro del proyecto viaja sin cifrar** — del borde al proxy, y
  del proxy al origen, ambos en claro sobre la red privada. Lo mismo ocurre con
  la instalación mediante `docker compose`, pero conviene dejarlo escrito.
- **La cobertura del filtro está medida, y es parcial.** Ver
  `filtering-coverage-findings.es.md`: las variantes ofuscadas de los vectores
  del corpus pasan, y tres clases de ataque todavía no tienen firma. Desplegar
  esto es estrictamente mejor que un origen sin filtrar, y no es lo mismo que
  estar cubierto.
