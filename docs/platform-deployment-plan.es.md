---
title: "Plan de despliegue en plataformas"
project: "open-shield"
date: "2026-11-26"
language: "es"
---

# Plan de despliegue en plataformas

La promesa de instalación de este proyecto es un comando: `make up` en un host
propio. `deploy-railway.md` muestra lo que esa promesa cuesta en una plataforma
gestionada: una docena de servicios cableados a mano, cuatro ajustes que fallan
en silencio y un hash de contraseña generado en otra máquina. Este documento
planifica cómo volver a *un solo paso* en las plataformas que la gente usa de
verdad, y dice con claridad cuáles no pueden alojar open-shield en absoluto.

Es un plan, no una guía. Nada de lo que aquí se describe está implementado
todavía; cada fase del §6 termina en un archivo del repositorio y en un
documento de despliegue trabajado como `deploy-railway.md`.

---

## 1. Qué debe ofrecer una plataforma

open-shield son tres procesos de larga duración y dos almacenes de datos. Una
plataforma puede alojarlo solo si ofrece todas las filas de abajo. Las dos
últimas son las que separan un despliegue que filtra de uno que solo lo aparenta.

| Requisito | Por qué |
|---|---|
| Contenedores de larga duración | OpenResty mantiene conexiones keepalive con el engine; el engine ejecuta la goroutine única de escritura de auditoría (`internal/audit/writer.go`). Ninguno sobrevive a un runtime limitado a una petición. |
| Red privada entre servicios | El engine responde `/v1/decide` y `/v1/audit` sin autenticación. Nunca debe tener una dirección pública. |
| PostgreSQL y Redis | La cadena de hashes y el límite de tasa con ventana deslizante. |
| Una entrada pública para el proxy y otra para el dashboard | Todo lo demás queda privado. |
| Una cabecera de dirección del cliente que el borde **sobrescribe** | `ipblock`, `ratelimit` y el limitador de acceso se basan en ella. Una cabecera que el cliente puede extender es una dirección falsificada (ver `OS_TRUSTED_PROXY` en `deploy/.env.example`). |
| Un origen accesible solo de forma privada | Un origen con URL pública propia esquiva todas las reglas de la cadena. |

### No alojables: Vercel, Netlify, Cloudflare Pages

Son plataformas de sitios estáticos y funciones serverless. Las funciones viven
lo que dura una petición, no tienen proceso persistente, no pueden ejecutar
OpenResty y no ofrecen red privada entre servicios. No hay dónde poner el engine
ni su escritor único, y ejecutar el escritor en cada invocación bifurcaría la
cadena: el único fallo que el registro forense existe para descartar.

Lo que *sí* pueden alojar es el frontend estático de la propia aplicación
protegida, con su URL de API apuntando al dominio del proxy. Es una topología
soportada —es exactamente como el frontend queda fuera del filtro en
`deploy-railway.md`—, pero no es un despliegue de open-shield, y este plan no
persigue uno.

---

## 2. Los cuatro ajustes portables

Toda topología gestionada reutiliza los cuatro ajustes que introdujo
`deploy-railway.md`. Solo cambian sus valores según la plataforma:

| Ajuste | Decide | Según la plataforma |
|---|---|---|
| `OS_LISTEN_PORT` / `PORT` | el puerto en el que escucha el proxy | lo inyecta la plataforma |
| `OS_RESOLVER*` | cómo resuelve OpenResty los nombres privados | depende de si el DNS privado es IPv4, IPv6 o ambos |
| `OS_TRUSTED_PROXY` | qué pares pueden fijar la dirección del cliente | el rango de direcciones del borde |
| `OS_REAL_IP_HEADER` | qué cabecera la transporta | la cabecera que el borde sobrescribe |

**Los dos últimos se miden siempre, nunca se copian de la documentación.** El
rango de Railway se leyó del propio log de acceso del proxy, y la cabecera que
la plataforma documentaba como segura resultó no enviarse en absoluto. Cada fase
de abajo repite esa medición antes de escribir su documento.

---

## 3. Railway: de guía a plantilla

Las plantillas de Railway describen un proyecto entero —servicios, almacenes de
datos, variables y las referencias entre ellos— y lo despliegan con un botón.
Los pasos manuales de `deploy-railway.md` §4 se traducen a una plantilla casi
uno a uno.

### 3.1 Qué contiene la plantilla

- `postgres` y `redis` del catálogo.
- `engine` desde `engine/Dockerfile`, sin dominio público, health check `/readyz`.
- `dashboard` desde `dashboard/api/Dockerfile`, dominio público en `8081`,
  health check `/healthz`.
- `proxy` desde `/proxy`, dominio público en `80`, health check
  `/__openshield/health`.
- Todas las variables de `deploy-railway.md` §4, con las referencias entre
  servicios (`${{Postgres.DATABASE_URL}}`, `engine.railway.internal`) ya
  rellenadas, y `OS_RESOLVER_IPV6=on`, `OS_TRUSTED_PROXY=100.64.0.0/10`,
  `OS_REAL_IP_HEADER=X-Forwarded-For` y `OS_SECURE_COOKIES=true` predefinidas.
- `OS_SESSION_SECRET` generado por la propia plantilla (con la función de
  generación de secretos de las plantillas de Railway; confirmar su nombre
  actual antes de publicar).

### 3.2 Qué sigue aportando quien despliega

Tres valores, que la plantilla pide:

1. **`OS_BACKEND_URL`**: la dirección privada de la aplicación a proteger. La
   plantilla no puede contener el origen: es un servicio del propio usuario.
2. **`OS_ADMIN_USER`**: por defecto `admin`.
3. **La contraseña del administrador**: ver §3.3.

### 3.3 El único cambio de código que necesita

Hoy el dashboard acepta solo `OS_ADMIN_PASSWORD_HASH`, lo que obliga a ejecutar
`make hash-password` en una máquina con Docker antes de desplegar: justo el paso
que una instalación de un botón existe para eliminar. Es también el paso con más
probabilidades de fallar: el escapado `$$` que Compose exige y Railway no ya ha
producido un hash que no corresponde a ninguna contraseña.

Propuesta: aceptar **`OS_ADMIN_PASSWORD`** como alternativa. Al arrancar, el
dashboard la hashea con bcrypt, conserva solo el hash en memoria y registra un
aviso recomendando la forma con hash. Definir ambas es un error de arranque,
como cualquier otra configuración mal formada. El compromiso —un secreto en
claro en el almacén de variables de la plataforma— es el mismo que ya asumen
`OS_SESSION_SECRET` y las contraseñas de los almacenes de datos, y debe quedar
registrado en `implementation-decisions.md` junto con la entrada del ajuste en
`deploy/.env.example`.

### 3.4 Qué sigue siendo manual, y debe decirse

- **Quitar el dominio público del origen.** Una plantilla no puede tocar un
  servicio que no creó. La descripción de la plantilla y la página posterior al
  despliegue deben convertir esto en la primera instrucción, no en una nota al
  pie: hasta que se haga, el despliegue no filtra nada.
- **Apuntar el frontend al proxy** y redesplegarlo (`VITE_API_URL` se fija en
  tiempo de compilación).
- **Los orígenes de CORS y CSRF** en el backend.

### 3.5 Terminado cuando

- La plantilla despliega un stack funcional sin ningún paso fuera de Railway.
- `scripts/smoke.sh` pasa contra él sin cambios.
- La comprobación de direcciones de origen de `deploy-railway.md` §6 muestra
  direcciones reales de clientes.
- `deploy-railway.md` empieza con el botón de la plantilla y conserva el
  procedimiento manual como referencia de lo que hace la plantilla.

---

## 4. Hosts propios: un comando, al pie de la letra

En un VPS la promesa original ya se cumple; lo que falta es la instalación
*previa* a `make up-prod`: Docker, el clon, los secretos. Es la fase de mayor
valor porque cubre a todos los proveedores a la vez.

**Objetivos:** Hetzner Cloud, Droplets de DigitalOcean, Akamai/Linode, Vultr,
OVH, AWS Lightsail y EC2, Google Compute Engine, máquinas virtuales de Azure:
cualquier host Linux con dirección pública.

**Plan:**

- `scripts/install.sh`: comprueba si está Docker y lo instala si falta, clona el
  repositorio, genera `OS_SESSION_SECRET`, pide la contraseña de administrador y
  `OS_BACKEND_URL`, escribe `deploy/.env` (haciendo por el usuario el escapado
  `$$`) y ejecuta `make up-prod`. Debe ser idempotente y negarse a sobrescribir
  un `deploy/.env` existente.
- El mismo script sirve como **user data de cloud-init**, de modo que el
  formulario de "crear servidor" de la mayoría de proveedores se convierte en el
  único paso.
- **PaaS autoalojados sobre un VPS** (Coolify, Dokploy, CapRover) despliegan un
  archivo Compose directamente. `deploy/docker-compose.yml` debería funcionar sin
  cambios; verificarlo en uno de ellos y documentar cualquier diferencia en lugar
  de bifurcar el archivo.

**Ajustes:** ninguno de los cuatro del §2 cambia: los clientes conectan
directamente, así que `OS_TRUSTED_PROXY` queda vacío. Si el usuario pone
Cloudflare delante, vuelve a ser el caso de borde gestionado:
`OS_REAL_IP_HEADER=CF-Connecting-IP` con los rangos publicados por Cloudflare
como `OS_TRUSTED_PROXY`.

---

## 5. Plataformas gestionadas

Ordenadas por lo cerca que quedan de un solo paso. Los nombres de cabecera y los
rangos de direcciones de esta tabla son puntos de partida tomados de la
documentación de cada plataforma y **deben medirse** (§2) antes de escribir un
documento.

| Plataforma | Mecanismo de un paso | Red privada | Almacenes de datos | Cabecera de dirección del cliente | Veredicto |
|---|---|---|---|---|---|
| **Railway** | Plantilla | `*.railway.internal`, solo IPv6 | Postgres y Redis del catálogo | `X-Forwarded-For`, borde desde `100.64.0.0/10` (medido) | Soportado, plantilla planificada (§3) |
| **Render** | Blueprint (`render.yaml`) + botón "Deploy to Render" | Servicios privados en la red interna | Postgres gestionado, Key Value (compatible con Redis) | Por medir | Muy adecuado; el Blueprint es un archivo del repo |
| **DigitalOcean App Platform** | App spec + botón "Deploy to DigitalOcean" | Puertos de servicio internos | Postgres gestionado, almacén gestionado compatible con Redis | `do-connecting-ip` (por medir) | Muy adecuado |
| **Koyeb** | Definición de servicio, botón de despliegue | Malla de servicios privada | Postgres gestionado; Redis externo | Por medir | Posible; Redis es una dependencia externa |
| **Fly.io** | `fly.toml` por app; no hay un archivo multi-app | 6PN, `*.internal`, IPv6 | Postgres gestionado; Redis vía Upstash | `Fly-Client-IP` | Posible; necesita un script de lanzamiento para tres apps |
| **Google Cloud Run** | Nada nativo para varios servicios | Ingress interno + conector VPC | Cloud SQL, Memorystore | `X-Forwarded-For`, añadido por el front end de Google | Posible, pesado; terreno de Terraform |
| **AWS ECS / App Runner** | Nada nativo | VPC | RDS, ElastiCache | `X-Forwarded-For` vía ALB | Fuera de alcance en v1: la vía VPS cubre AWS |
| **Heroku** | `heroku.yml`, botón | **Solo en Private Spaces (de pago)** | Add-ons de Postgres y Redis | `X-Forwarded-For`, añadido por el router | No soportado fuera de Private Spaces: el engine necesitaría una dirección pública |
| **Vercel, Netlify, Cloudflare Pages** | — | — | — | — | No pueden alojarlo (§1) |

Notas sobre las filas que necesitan algo más que un archivo:

- **Render y DigitalOcean** describen el stack entero de forma declarativa, como
  una plantilla de Railway, pero la descripción vive *en el repositorio*
  (`deploy/render.yaml`, `.do/deploy.template.yaml`). Eso las hace revisables y
  comprobables en CI, cosa que una plantilla guardada en la plataforma no es.
- **Fly.io** no tiene manifiesto multi-app. Un `fly.toml` por servicio más un
  `scripts/fly-launch.sh` que cree las tres apps, conecte los almacenes de datos
  y fije los secretos es lo más cercano a un solo paso.
- **Heroku** enruta el tráfico entre dynos solo a través del router público,
  salvo que la app esté en un Private Space. Un engine público que responde
  veredictos sin autenticación es la única topología que este proyecto no debe
  publicar.

---

## 6. Fases

| Fase | Entregable | Cubre |
|---|---|---|
| 1 | `OS_ADMIN_PASSWORD` (§3.3) | Elimina el paso fuera de la plataforma en toda instalación gestionada |
| 2 | `scripts/install.sh` + cloud-init (§4) | Todos los proveedores de VPS |
| 3 | Plantilla de Railway (§3) | El despliegue que ya está en uso |
| 4 | `deploy/render.yaml` y app spec de DigitalOcean | Dos plataformas de un botón, definidas en el repo |
| 5 | Configuración de Fly.io y script de lanzamiento | Fly.io |
| — | Cloud Run, ECS, Koyeb | Bajo demanda; mientras tanto la vía VPS cubre a esos proveedores |
| — | Heroku fuera de Private Spaces, Vercel, Netlify, Cloudflare Pages | No planificado (§1, §5) |

La fase 1 va primero porque todas las siguientes dependen de ella: sin ella,
cada instalación de un botón sigue empezando por "primero, instala Docker en
otra máquina y hashea tu contraseña".

Cada fase está terminada cuando:

1. su despliegue pasa `scripts/smoke.sh` sin cambios;
2. la lista de eventos muestra direcciones de cliente reales y distintas: la
   comprobación que demuestra que `OS_TRUSTED_PROXY` y `OS_REAL_IP_HEADER` son
   correctos;
3. el engine no tiene dirección pública, verificado desde fuera;
4. existen un `docs/deploy-<plataforma>.md` y su traducción `.es.md`, escritos a
   partir de los valores medidos y no de los documentados.
