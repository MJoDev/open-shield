# Decisiones de implementación

Registro de dónde el código se aparta del
[documento técnico](documento-tecnico.md), y por qué. El documento
técnico sigue siendo el diseño; esto es lo que se encontró al construirlo.

Las secciones (§) se refieren al documento técnico.

---

## 1. `access_by_lua` en lugar de `auth_request` (§3.2, §4.4, §7.2)

**El documento:** Nginx invoca al motor mediante una subpetición interna
`auth_request`.

**El código:** `access_by_lua` con lectura acotada del cuerpo.

**Por qué:** el módulo `auth_request` de Nginx **descarta el cuerpo de la
petición** — la subpetición de autorización solo recibe cabeceras. RF-03 exige
filtrar payloads de SQLi y XSS, y en un `POST` esos payloads viajan en el
cuerpo. Con `auth_request`, las reglas `sqli` y `xss` habrían sido ciegas ante
el vector más común.

La decisión tecnológica del §4.4 no cambia: sigue siendo Lua sobre
Nginx/OpenResty, con el proxy como capa delgada que delega. Solo cambia el
mecanismo de invocación, que además ahorra la subpetición interna.

El test que lo verifica está en `scripts/smoke.sh`:
`XSS en el cuerpo del POST → 403`.

**Consecuencia operativa:** el cuerpo se lee hasta
`OS_MAX_BODY_INSPECT_BYTES` (8 KiB por defecto). Más allá de
`client_body_buffer_size`, Nginx vuelca el cuerpo a disco y el motor lo recibe
marcado como truncado en lugar de leerlo de vuelta desde el sistema de archivos
en el camino de la petición.

---

## 2. La función de hash del §6.2 no es determinista

**El documento:**

```go
raw := e.PrevHash + e.Timestamp.String() + fmt.Sprint(e.Payload)
```

**El problema:** `Payload` es un `map[string]any`, y Go aleatoriza el orden de
iteración de los mapas en cada ejecución. El mismo registro produce un hash
distinto cada vez que se calcula. Es decir: `VerifyChain` reportaría
manipulación sobre una cadena perfectamente intacta, y todo el mecanismo
forense del §6 — que es el aporte central de la propuesta — no funcionaría.

`Timestamp.String()` añade un segundo problema menor: su salida depende de la
zona horaria y de si el `time.Time` lleva lectura monotónica adjunta.

**El código:** codificación canónica en `internal/model/canonical.go`.

```
hash = sha256( prevHash | id | requestID | ts | kind | canonicalJSON(payload) )
```

- JSON canónico: claves ordenadas recursivamente, sin espacios, sin escape HTML.
- Timestamp en `RFC3339Nano` normalizado a UTC.
- Cada campo va precedido de su longitud en 8 bytes, para que ninguna
  combinación de valores pueda reinterpretarse como un conjunto distinto de
  campos (`{"ab","c"}` y `{"a","bc"}` deben dar hashes distintos).
- `ID`, `RequestID` y `Kind` entran en el hash. En el boceto quedaban fuera y
  podían reescribirse sin romper la cadena.

Los tests en `internal/model/audit_test.go` cubren cada una de estas
propiedades, incluido el determinismo sobre 1.000 recálculos.

### 2.1 Normalización antes de sellar

El payload se normaliza (`NormalizePayload`) antes de calcular el hash: todo
número pasa a `json.Number`, conservando su literal. Sin esto, un `float64`
sellado como `1.50` podría releerse de PostgreSQL como `1.5` y romper la
verificación sin que nadie hubiera tocado nada.

### 2.2 Truncado a microsegundos

`timestamptz` de PostgreSQL guarda microsegundos. El escritor trunca la marca
de tiempo a microsegundos **antes** de sellar, para que el valor que se hashea
sea exactamente el que vuelve en una lectura.

---

## 3. `audit` sube de `engine/internal/` a `internal/` de la raíz (§7)

**El documento:** `engine/internal/audit/`.

**El problema:** en Go, un paquete bajo `engine/internal/` solo puede
importarse desde `engine/…`. El dashboard necesita `AuditEntry` y la
verificación de cadena para la vista forense, así que el árbol propuesto no
compila.

**El código:** los paquetes compartidos (`model`, `audit`, `events`, `config`,
`migrate`, `rulestore`) están en `internal/` de la raíz del módulo. Los que son
privados del motor (`rules`, `ratelimit`) se quedan en `engine/internal/`. La
separación conceptual del documento se conserva.

La interfaz se llama `audit.Repository` en vez de `AuditRepository`, para no
repetir el nombre del paquete. Sus dos métodos del §5.3 están intactos;
`VerifyChain` devuelve un `VerifyResult` en lugar de un `bool` porque, ante una
cadena rota, la primera pregunta del operador es *dónde*, y solo el store puede
responderla mientras recorre el histórico.

---

## 4. Un único escritor del log, y es asíncrono

El documento no lo fija. Es una decisión con dos motivos y una consecuencia.

**Correctitud.** El hash de cada entrada cubre el de la anterior, así que los
`append` tienen que ocurrir en orden estricto. Dos goroutines sellando contra
el mismo head bifurcarían la cadena en dos ramas que ya no verifican. El
escritor es un único goroutine detrás de un canal (`internal/audit/writer.go`).

**Latencia.** El §8.2 fija un presupuesto de 50 ms añadidos. Bloquear la
petición en un `INSERT` gastaría ese presupuesto en contabilidad. El veredicto
vuelve al proxy en cuanto las reglas deciden, y la entrada se escribe detrás.

**Consecuencia:** existe una ventana breve en la que una decisión se sirvió pero
aún no es durable. `Close` drena la cola al apagar, de modo que la ventana está
acotada por el apagado y no por una pérdida. Si la cola se llena, las entradas
se descartan y se cuentan — nunca a costa de bloquear una petición — y el
contador es visible.

### 4.1 El dashboard no escribe en la cadena

Por lo mismo: dos procesos escribiendo la bifurcarían. El dashboard registra
sus acciones administrativas llamando a `POST /v1/audit` del motor, que es
síncrono.

Y lo hace **antes** de aplicar el cambio. Si la entrada no puede confirmarse,
el cambio no se aplica y la API responde 503. Un cambio en lo que el proxy
bloquea del que nadie pueda dar cuenta después es peor que un cambio que no
ocurrió.

La excepción es el inicio de sesión, que se registra en modo best-effort:
negar el acceso al panel porque el motor no responde dejaría al operador sin la
herramienta que necesita justamente para averiguar por qué no responde.

---

## 5. Política ante motor caído: `OS_FAIL_MODE`

El documento no lo fija. Por defecto **`open`**: si el motor no responde dentro
de `OS_DECIDE_TIMEOUT_MS`, la petición pasa y el fallo se registra.

Una capa de protección que tumba el sitio protegido cada vez que su propio
plano de control parpadea ha invertido su propósito, y el §8.2 fija un objetivo
de disponibilidad ≥99% que ningún requisito de filtrado supera. `closed`
invierte el criterio donde una petición sin filtrar sea peor que una petición
sin servicio.

El mismo criterio se aplica dentro del motor: si Redis no responde, la regla de
rate limiting permite la petición y cuenta el fallo, en vez de rechazar todo el
tráfico porque el contador está caído.

---

## 6. Qué no se registra

El §6.1 pide registrar «cabeceras relevantes». La implementación decide qué es
relevante excluyendo lo que no debe persistirse:

- **El cuerpo de la petición no se almacena.** Se inspecciona y se descarta. Un
  log append-only con retención larga es el peor sitio posible para las
  contraseñas y datos personales que viajan en un `POST`.
- **`Cookie` y `Authorization` no se almacenan.** Un log de auditoría que
  guarda tokens de sesión se convierte en un almacén de credenciales.

Lo que sí queda es el fragmento acotado (60 caracteres alrededor de la
coincidencia, sin caracteres de control) que disparó el bloqueo. Es la
evidencia de *por qué* se bloqueó, que es lo que el §6 pide.

---

## 7. Detalles menores

**Orden de la cadena de reglas.** `ipblock → ratelimit → sqli → xss`. Lo más
barato primero: una comparación de prefijos, luego un viaje a Redis, y solo
entonces el escaneo del contenido. Un cliente ya conocido nunca llega a las
comprobaciones caras.

**`Decide` recibe el contexto como parámetro.** El §5.2 lo guarda en el motor
(`e.ctx`). El contexto pertenece a la petición que se está decidiendo y lleva
su plazo; guardarlo en la estructura es un antipatrón en Go. La interfaz `Rule`
queda literal como en el documento.

**Status HTTP por regla.** El rate limiting responde 429 y el resto 403, a
través de una interfaz opcional `BlockStatus()`. La distinción no es cosmética:
un cliente correcto lee 429 como «espera y reintenta», mientras que 403 le dice
que se rinda.

**Sin backreferences en las firmas.** Go usa RE2, que no las soporta. La firma
`bare_tautology` detecta cualquier comparación numérica (`or 1=2` además de
`or 1=1`), que sigue siendo un intento de inyección.

**Ordenación por `seq`, no por marca de tiempo.** Dos peticiones pueden caer en
el mismo microsegundo y `timestamptz` no las distinguiría. El orden de la
cadena es el orden de inserción.

**Anclaje al verificar un rango.** Verificar desde una fecha usa como ancla el
hash de la entrada inmediatamente anterior al rango. Sin ese ancla, una primera
entrada reescrita de forma internamente consistente pasaría la verificación.

**Un `$` en el hash bcrypt rompe la instalación.** Docker Compose interpreta
`$` en un `.env` como referencia a variable, así que `$2a$10$…` llega vacío al
contenedor sin ningún error visible. `-hash-password` imprime la línea ya
escapada con `$$`, y `.env.example` lo advierte.

**Ruta del módulo Go.** `github.com/open-shield/open-shield`. Si el
repositorio acaba publicado bajo otro propietario, es un `sed` sobre los
imports y una línea en `go.mod`.

---

## Fuera de alcance en esta versión

Con su punto de anclaje ya preparado:

| Requisito | Estado | Anclaje |
|---|---|---|
| RF-04 · TLS y certbot | Diferido | Bloque `443` y webroot ACME comentados en `proxy/conf.d/openshield.conf.template` |
| RF-07 · Notificación de anomalías | Diferido | Los eventos ya se publican en Redis; falta el suscriptor |
| RF-08 · Balanceo de carga | Diferido | `proxy_pass` sobre variable; falta el bloque `upstream` con varios miembros |
| Geo-IP | Diferido | El payload de auditoría es un mapa abierto |
| SQLite | Diferido | `audit.Repository` ya tiene dos implementaciones (Postgres y memoria) |
| Control-plane multi-VPS | Excluido en el §2 | — |
