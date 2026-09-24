# Manual de operación

*[English](operations-manual.md)*

Despliegue, ajuste y diagnóstico de open-shield.

---

## 1. Requisitos

| | |
|---|---|
| Sistema | Linux con Docker Engine 24+ y Compose v2 |
| Red | IP pública, DNS apuntando al servidor, puertos 80/443 abiertos |
| Recursos | 1 vCPU y 1 GB de RAM bastan para el stack completo con tráfico moderado |
| Almacenamiento | El log de auditoría crece de forma continua — ver §6 |

El backend protegido puede estar escrito en cualquier tecnología: lo único que
se le pide es exponer un puerto HTTP alcanzable desde la red del stack.

---

## 2. Instalación

```bash
git clone <repositorio> && cd open-shield
cp deploy/.env.example deploy/.env
```

### 2.1 Secretos

Los tres son obligatorios; el stack no arranca sin ellos.

```bash
openssl rand -base64 24     # → POSTGRES_PASSWORD
openssl rand -hex 32        # → OS_SESSION_SECRET
make hash-password PASSWORD='la contraseña del administrador'
```

El último comando imprime la línea completa para pegar en `deploy/.env`.

> **Los `$$` del hash son obligatorios.** Docker Compose interpreta un `$`
> suelto en un `.env` como el inicio de una variable. Un hash bcrypt empieza por
> `$2a$10$`, así que pegarlo sin escapar hace que el contenedor reciba una
> cadena vacía — y el único síntoma es que ninguna contraseña funciona nunca.

### 2.2 El backend a proteger

En `deploy/.env`:

```ini
OS_BACKEND_URL=http://mi-aplicacion:8000
OS_SERVER_NAME=ejemplo.com
```

Si la aplicación ya corre en otro stack de Compose, conéctala a la red
`openshield` o publica su puerto en la red interna del host.

`OS_SERVER_NAME=_` acepta cualquier cabecera `Host`, que es lo que se quiere
mientras se prueba contra `localhost` o una IP. En producción, pon el dominio
real.

### 2.3 Arranque

```bash
make up-prod                 # tu backend
make up                      # con la aplicación de demostración incluida
```

El motor aplica las migraciones al arrancar; no hay ningún paso manual de
esquema.

### 2.4 Verificación

```bash
OS_ADMIN_PASSWORD='...' make smoke
```

Catorce comprobaciones: tráfico legítimo, filtrado de SQLi y XSS en query y en
cuerpo, rate limiting, autenticación del dashboard e integridad de la cadena.

---

## 3. Ajuste

Todo se configura por variables de entorno en `deploy/.env`. Tras cambiarlas:
`docker compose -f deploy/docker-compose.yml up -d`.

### 3.1 Rate limiting

```ini
OS_RATELIMIT_REQUESTS=100
OS_RATELIMIT_WINDOW_S=60
```

Es una ventana deslizante por dirección de origen, no una ventana fija: un
cliente no puede enviar el doble del límite aprovechando el cambio de ventana.

**Cómo elegir el valor.** Mira `Peticiones` en el dashboard durante un día
normal y divide por el número de visitantes distintos. Empieza en tres o cuatro
veces ese número. Una página con muchos recursos estáticos consume el
presupuesto rápido — si el proxy también sirve imágenes y CSS, sube el límite.

**Si bloquea a usuarios legítimos:** casi siempre es NAT. Toda una oficina, o
una operadora móvil, comparte una IP pública. Añade su rango a la lista de
permitidos desde la pestaña **Reglas** en vez de subir el límite global.

### 3.2 Inspección del cuerpo

```ini
OS_MAX_BODY_INSPECT_BYTES=8192
```

Cuántos bytes del cuerpo examinan las reglas `sqli` y `xss`. Más cobertura
cuesta más trabajo en el camino de la petición. `0` desactiva la inspección del
cuerpo (no recomendado: es donde viaja el payload de un `POST`).

Los cuerpos que superan `client_body_buffer_size` (64 KiB) los vuelca Nginx a
disco y llegan al motor marcados como truncados, en lugar de releerse desde el
sistema de archivos.

### 3.3 Firmas de detección

Las firmas de SQLi y XSS viven en un archivo JSON versionado aparte del código,
para poder actualizarlas sin recompilar (§8.2). Para sustituirlas:

```yaml
# deploy/docker-compose.yml, servicio engine
volumes:
  - ./mis-firmas.json:/etc/openshield/patterns.json:ro
environment:
  OS_PATTERNS_FILE: /etc/openshield/patterns.json
```

Parte de `engine/internal/rules/patterns.json`. Son expresiones RE2: sin
backreferences, tiempo lineal, sin backtracking catastrófico — importante,
porque se ejecutan sobre entrada controlada por el atacante.

Una firma mal formada **impide arrancar el motor**, deliberadamente: es mejor
que fallar en silencio sobre tráfico real.

### 3.4 Comportamiento ante fallo

```ini
OS_FAIL_MODE=open
OS_DECIDE_TIMEOUT_MS=150
```

`open` (por defecto) deja pasar la petición si el motor no responde a tiempo, y
lo registra. `closed` responde 503.

Elige `closed` solo donde una petición sin filtrar sea peor que una petición sin
servicio. Para un sitio público con objetivo de disponibilidad del 99%, `open`
es la elección correcta.

---

## 4. Operación diaria

### 4.1 El dashboard

`http://<servidor>:8081`

| Pestaña | Para qué |
|---|---|
| **En vivo** | Volumen, tasa de bloqueo, IP y reglas que más disparan, y el feed de decisiones en tiempo real |
| **Auditoría** | El histórico completo, con filtros por tipo, resultado e IP. Cada fila se despliega con su payload y sus hashes |
| **Reglas** | Activar y desactivar reglas, y administrar la lista de acceso por IP |
| **Forense** | Verificación de la cadena de integridad |

El indicador de conexión junto al selector de ventana distingue un sistema
ocioso de uno sin feed. Si dice *Reconectando…* durante más de un minuto, revisa
Redis.

### 4.2 Bloquear un atacante

Pestaña **Reglas** → *Lista de acceso por IP*. Se acepta una dirección suelta o
un CIDR; una entrada `permitir` gana sobre una `bloquear`, así que puedes
bloquear un rango entero y dejar pasar una dirección concreta dentro de él.

El cambio llega al motor en menos de un segundo por el canal de control de
Redis, y como respaldo el motor relee la configuración cada 30 segundos.

### 4.3 Investigar un reclamo

Cuando un usuario reporta que fue bloqueado, la página de bloqueo le muestra un
identificador. Con él:

**Auditoría** → filtro por IP, o directamente:

```bash
curl -s -b cookies.txt \
  "http://localhost:8081/api/v1/events?request_id=<el-identificador>"
```

Ese mismo identificador viaja en la cabecera `X-Request-ID` hasta el backend y
aparece en el log operativo del proxy, así que la petición puede seguirse por
las tres capas.

### 4.4 Verificar la integridad

Pestaña **Forense** → *Verificar cadena*. Sin fechas se verifica el histórico
completo.

Hazlo de forma rutinaria, y siempre antes de usar el log como evidencia de un
incidente. Si el resultado es `Cadena rota`, el informe nombra la entrada
exacta, su posición y qué falló: un hash que no coincide significa contenido
modificado; un enlace roto significa un registro borrado, reordenado o
insertado.

---

## 5. Rendimiento

### 5.1 Latencia medida

Medición sobre el stack de demostración (Docker Desktop, WSL2), 100 peticiones
por objetivo, desde dentro de la red del stack:

| | p50 | p95 |
|---|---|---|
| Backend directo | 1,29 ms | 1,76 ms |
| A través del proxy, cadena completa | 2,63 ms | 3,41 ms |
| **Sobrecarga añadida** | **+1,3 ms** | **+1,7 ms** |

Frente al presupuesto de **< 50 ms** del §8.2, queda un margen de más de un
orden de magnitud.

Los números de la tabla son de una medición manual con `curl`, conservada como
referencia histórica. Para repetirla de forma reproducible:

```bash
make up-load     # el stack con el rate limiting desactivado para medir
make test-load   # k6, cuatro escenarios, ~1 minuto
```

La corrida imprime la misma comparación y falla con código ≠ 0 si la sobrecarga
sale del presupuesto del §8.2. `make test-load-full` hace la versión de nueve
minutos.

El rate limiting se desactiva durante la medición a propósito: el motor
identifica al cliente por la dirección de origen, todos los usuarios virtuales
salen de una sola, y con el límite por defecto la corrida se estrangularía a sí
misma y mediría el limitador. Ver `docs/testing-strategy.es.md` §4.5.

### 5.2 De dónde sale la sobrecarga

Una llamada HTTP al motor sobre conexión reutilizada, una evaluación de la
cadena de reglas y, para el rate limiting, un viaje a Redis. La escritura del
log **no** está en el camino: el veredicto vuelve antes de que empiece.

Si la latencia sube:

- **Cuerpos grandes** — el escaneo es proporcional a
  `OS_MAX_BODY_INSPECT_BYTES`. Bájalo.
- **Redis lento** — solo afecta a la regla `ratelimit`. `docker stats redis`.
- **Firmas propias costosas** — un patrón con alternancias anidadas puede ser
  caro incluso en RE2. Mide antes y después.

### 5.3 Cola de auditoría

`OS_AUDIT_BUFFER=4096` es la profundidad de la cola entre el camino de la
petición y la base de datos. Si se llena, las entradas se descartan y se
cuentan; nunca se bloquea una petición por escribir el log.

El contador `dropped` está en `/api/v1/status`. Si crece, la base de datos no
sigue el ritmo del tráfico: revisa la E/S de disco antes de subir el buffer,
porque un buffer mayor solo alarga el momento en que empieza a descartar.

---

## 6. Mantenimiento

### 6.1 Crecimiento del log

Cada petición genera una entrada. Con tráfico continuo el log crece de forma
sostenida y **no puede podarse**: borrar filas rompe la cadena, exactamente como
lo haría un atacante.

```sql
SELECT pg_size_pretty(pg_total_relation_size('audit_log')),
       count(*), min(ts), max(ts)
FROM audit_log;
```

Cuando haya que archivar, el procedimiento correcto es **exportar el tramo
completo con sus hashes** (para que siga siendo verificable de forma
independiente) y solo entonces recrear el volumen. La cadena nueva arranca desde
el hash génesis, y esa discontinuidad queda documentada por el archivo
exportado.

### 6.2 Copias de seguridad

```bash
docker compose -f deploy/docker-compose.yml exec -T db \
  pg_dump -U openshield openshield | gzip > auditoria-$(date +%F).sql.gz
```

Verifica la cadena **antes** de cada copia: un respaldo de un log ya corrupto
conserva la corrupción.

Redis no necesita respaldo. Solo guarda contadores de rate limiting y el canal
de eventos, ambos reconstruibles; por eso su persistencia está desactivada.

### 6.3 Actualizaciones

```bash
git pull
docker compose -f deploy/docker-compose.yml up -d --build
```

Las migraciones se aplican solas al arrancar el motor, bajo un lock de
PostgreSQL, así que varias instancias arrancando a la vez no compiten.

El log de auditoría sobrevive a la actualización: vive en el volumen `db-data`.
`make clean` **sí** lo borra.

### 6.4 Rotar el secreto de sesión

Cambiar `OS_SESSION_SECRET` invalida todas las sesiones abiertas. Es la forma de
expulsar a todo el mundo tras una sospecha de compromiso.

---

## 7. Diagnóstico

### El proxy responde 502

El backend no es alcanzable desde la red del stack.

```bash
docker compose -f deploy/docker-compose.yml exec proxy \
  curl -sv "$OS_BACKEND_URL" 2>&1 | head -20
```

Comprueba que `OS_BACKEND_URL` usa el nombre del servicio, no `localhost`:
dentro de un contenedor, `localhost` es el propio contenedor.

### Todo pasa sin filtrarse

El motor está caído y `OS_FAIL_MODE=open` hace su trabajo. Busca
`engine unreachable` en los logs del proxy:

```bash
docker compose -f deploy/docker-compose.yml logs proxy | grep openshield
docker compose -f deploy/docker-compose.yml logs engine | tail -40
```

### El dashboard rechaza la contraseña correcta

Casi siempre es el escapado del `$` (§2.1). Comprueba qué llega al contenedor:

```bash
docker compose -f deploy/docker-compose.yml exec dashboard-api \
  sh -c 'echo "$OS_ADMIN_PASSWORD_HASH"'
```

Debe empezar por `$2a$`. Si está vacío o truncado, faltan los `$$`.

La otra causa es `OS_SECURE_COOKIES=true` sirviendo por HTTP plano: el inicio de
sesión parece funcionar y la sesión no persiste, porque el navegador nunca
devuelve la cookie. Déjalo en `false` hasta que haya TLS.

### El feed en vivo no muestra nada

El motor publica en Redis y el dashboard se suscribe. Con el stack activo:

```bash
docker compose -f deploy/docker-compose.yml exec redis \
  redis-cli SUBSCRIBE openshield:events
```

Si ahí aparecen eventos y en el navegador no, el problema está en el WebSocket
(revisa la consola del navegador). Si tampoco aparecen ahí, el motor no está
publicando.

### El motor no arranca

Casi siempre es configuración: falta una variable obligatoria, o una firma del
archivo de patrones no compila. El error lo dice explícitamente:

```bash
docker compose -f deploy/docker-compose.yml logs engine | tail -20
```

---

## 8. Seguridad del propio sistema

- **Solo el proxy y el dashboard publican puertos.** El motor, Redis y
  PostgreSQL viven en la red interna. No los expongas.
- **Restringe el acceso al dashboard.** Puede cambiar lo que el proxy bloquea,
  así que llegar a él equivale a atravesar el proxy. Ponlo detrás de una VPN o
  limita `OS_DASHBOARD_PORT` a la red de administración con el cortafuegos del
  host.
- **El cortafuegos perimetral sigue siendo necesario.** El proxy protege el
  tráfico web; no impide que alguien alcance el backend directamente por otra
  ruta. Cierra todo lo que no sean 80 y 443 hacia el exterior.
- **Toda acción administrativa queda registrada** en la misma cadena, con su
  actor. Si la entrada no puede escribirse, el cambio no se aplica.

---

## 9. Reversión

El proxy es una capa delante del backend, así que revertir es sacarlo de en
medio:

```bash
docker compose -f deploy/docker-compose.yml stop proxy
```

y devolver el DNS o el cortafuegos al backend directamente. El backend nunca se
modificó, así que no hay nada que deshacer en él.

El log de auditoría permanece en el volumen y sigue siendo verificable.
