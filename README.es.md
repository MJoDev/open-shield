# open-shield

[English](README.md) · **Español**

Proxy inverso con motor de reglas y trazabilidad forense verificable.

Se instala delante de cualquier aplicación web con un solo comando. Toda petición
pasa por un motor de reglas antes de llegar al servidor de origen, y cada
decisión queda registrada en un log de auditoría encadenado por hashes: si
alguien altera o borra un registro, la verificación lo detecta y señala la
entrada exacta.

Implementación del [documento técnico de decisiones](docs/documento-tecnico.md).
Sin dependencias propietarias y sin acoplamiento a ninguna infraestructura
concreta: el mismo stack se instala igual en cualquier VPS.

---

## Arranque

Se necesita únicamente Docker.

```bash
git clone https://github.com/MJoDev/open-shield.git && cd open-shield
cp deploy/.env.example deploy/.env
```

Genera los tres secretos que `deploy/.env` marca como obligatorios:

```bash
openssl rand -base64 24     # POSTGRES_PASSWORD
openssl rand -hex 32        # OS_SESSION_SECRET

make hash-password PASSWORD='tu contraseña'   # OS_ADMIN_PASSWORD_HASH
```

> El comando imprime la línea ya escapada. Los `$$` del hash son intencionales:
> Docker Compose interpreta un `$` suelto como una variable, y pegar el hash sin
> escapar hace que el contenedor reciba un valor vacío sin ningún error visible.

Levanta el stack completo, con una aplicación de demostración incluida:

```bash
make up
```

| | |
|---|---|
| `http://localhost` | la aplicación protegida, detrás del proxy |
| `http://localhost:8081` | el dashboard |

Para proteger tu propia aplicación en lugar de la demo, apunta `OS_BACKEND_URL`
a ella en `deploy/.env` y usa `make up-prod`.

### Compruébalo

```bash
curl -i localhost/                                # 200 — pasa al backend
curl -i "localhost/?id=1'%20OR%20'1'='1"          # 403 — regla sqli
curl -i -X POST localhost/ -d "q=<script>x</script>"   # 403 — regla xss, en el cuerpo
```

O de una vez, incluyendo rate limiting e integridad del log:

```bash
OS_ADMIN_PASSWORD='tu contraseña' make smoke
```

---

## Qué hace

| | |
|---|---|
| **RF-01** | Intercepta toda conexión antes del servidor de origen |
| **RF-02** | Enruta hacia el backend configurado |
| **RF-03** | Filtra SQLi y XSS en ruta, query, cabeceras, cookies **y cuerpo** |
| **RF-05** | Limita peticiones por IP en ventana deslizante |
| **RF-06** | Registra cada conexión con integridad verificable |
| **RF-09** | Dashboard en tiempo real por WebSocket |
| **RF-10** | Instalación completa con un único comando |

Diferidos a la v1.1, con sus puntos de anclaje ya preparados: TLS y renovación
automática de certificados (RF-04), notificación ante tráfico anómalo (RF-07) y
balanceo de carga entre instancias (RF-08).

---

## Arquitectura

```
internet ──► proxy (OpenResty)
               │  access_by_lua → POST /v1/decide   [keepalive]
               ▼
            engine (Go)
               │  ipblock → ratelimit → sqli → xss     ← primer bloqueo gana
               ├──► Redis        ventana deslizante del rate limit
               │
               └──► escritor único ──► PostgreSQL   cadena de hashes
                                   └──► Redis Pub/Sub
                                             │
            dashboard-api (Go) ◄──────────────┘
               └── REST + WebSocket + React embebido
```

Cada petición lleva un `X-Request-ID` que la acompaña desde el proxy hasta la
entrada de auditoría y hasta el backend, de modo que una sola petición puede
seguirse por los tres.

**Desarrollo propio:** el motor de reglas, el esquema de trazabilidad forense y
el dashboard. **Infraestructura de terceros:** Nginx/OpenResty, Redis y
PostgreSQL, que se usan tal cual y sin lógica de negocio dentro.

### Estructura

```
internal/          modelo, cadena de auditoría, eventos, configuración
engine/            motor de reglas y decisión
dashboard/api/     REST, WebSocket y SPA embebido
dashboard/web/     interfaz React
proxy/             configuración OpenResty y el hook Lua
migrations/        esquema de PostgreSQL, aplicado al arrancar
examples/          aplicación de demostración
deploy/            docker-compose y .env.example
scripts/           prueba de humo y demostración forense
```

---

## Trazabilidad forense

Cada entrada del log guarda el hash de la anterior. Verificar consiste en
recorrer la cadena y recalcular:

```bash
curl -s -b cookies.txt localhost:8081/api/v1/audit/verify
# {"ok":true,"checked":1432}
```

La base de datos además rechaza cualquier `UPDATE` o `DELETE` sobre el log. Eso
hace la manipulación incómoda; la cadena la hace **detectable**, que es lo que
importa frente a un atacante que ya controla la base de datos:

```bash
OS_ADMIN_PASSWORD='tu contraseña' make tamper-demo
```

El script desactiva el trigger, reescribe un bloqueo como si hubiera sido
permitido, y vuelve a verificar:

```json
{
  "ok": false,
  "checked": 7,
  "broken_at": "fe5ec189-e4e2-4cdc-9738-6b0397c82d1d",
  "position": 7,
  "detail": "stored hash 8622dfd3ccff… does not match the recomputed hash 1cb8ecd17781… (this entry's content was modified after it was written)"
}
```

Borrar una entrada tampoco pasa desapercibido: los hashes restantes siguen
siendo válidos por separado, pero el enlace con la siguiente se rompe.

**Qué no se guarda:** el cuerpo de las peticiones y las cabeceras `Cookie` y
`Authorization`. Se inspeccionan, no se almacenan. Un log append-only con
retención larga es el peor lugar posible para contraseñas y tokens de sesión.
Lo que sí queda es el fragmento acotado que disparó el bloqueo, que es la
evidencia de *por qué* se bloqueó.

---

## Desarrollo

No hace falta Go instalado: todo corre en contenedor.

```bash
make test        # go vet + tests
make test-race   # con detector de carreras
make logs        # seguir los logs
make clean       # detener y BORRAR el log de auditoría
```

Para trabajar en la interfaz con recarga en caliente:

```bash
cd dashboard/web && npm install && npm run dev   # proxeado a localhost:8081
```

---

## Documentación

- [Documento técnico](docs/documento-tecnico.md)
  ([English](docs/technical-document.md))
- [Decisiones de implementación](docs/decisiones-implementacion.md) — dónde y
  por qué el código se aparta del documento técnico
- [Manual de operación](docs/manual-operacion.md) — despliegue, ajuste y
  diagnóstico

## Licencia

[Apache License 2.0](LICENSE).
