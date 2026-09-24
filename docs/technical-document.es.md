---
titulo: "Sistema de Proxy Inverso — Documento Técnico de Decisiones"
proyecto: "open-shield"
fecha: "2026-08-25"
version: "1.2 (borrador)"
revision: "2026-09-24"
licencia: "Open source"
idioma: "es"
version_en: "technical-document.md"
---

> **Estado de esta revisión.** La v1.2 incorpora los resultados de la evaluación
> de resistencia a evasión registrada en `filtering-coverage-findings.es.md`. Los
> puntos marcados **(propuesta)** están pendientes de aprobación y son los
> únicos que alteran lo acordado en la v1.1.

# Sistema de Proxy Inverso

## Documento Técnico Completo

**open-shield**
Sistema de proxy inverso para la protección de infraestructura web
DOCUMENTO TÉCNICO DE DECISIONES

---

### Datos Generales
- **Alcance:** Open source, portable a cualquier VPS, integrable en CI/CD
- **Área:** Computación y servicios de internet
- **Año:** 2026

---

### Índice de Secciones
1. Resumen ejecutivo
2. Alcance y objetivos
3. Arquitectura del sistema
4. Decisiones tecnológicas
5. Patrones de diseño aplicados
6. Trazabilidad forense
7. Estructura del repositorio
8. Requerimientos
9. Viabilidad
10. Cronograma tentativo
11. Conclusiones

---

### 1. Resumen Ejecutivo

El documento formaliza las decisiones de desarrollo de un sistema de proxy inverso concebido como proyecto open source de uso general: "instalable en cualquier VPS con un solo comando, sin costo de licenciamiento, e integrable en un pipeline de CI/CD sin pasos manuales."

El alcance no se limita al proxy en sí, sino que incluye el motor de reglas y decisión, dashboard de administración y esquema de trazabilidad forense como desarrollos originales.

---

### 2. Alcance y Objetivos

**Objetivo General:**
"Diseñar e implementar un sistema de proxy inverso que actúe como capa de protección perimetral para infraestructura web, mitigando accesos no autorizados y tráfico malicioso sin alterar las aplicaciones existentes, y distribuible como software open source de instalación inmediata."

**Objetivos Específicos:**

1. Diagnosticar el nivel de exposición de una infraestructura web ante conexiones directas desde internet

2. Diseñar la arquitectura del proxy inverso, motor de reglas, dashboard de monitoreo y esquema de trazabilidad forense "empaquetada como un stack de contenedores instalable en cualquier VPS"

3. Validar el sistema mediante pruebas de carga y simulacros de ataque controlados, incluyendo para cada vector sus variantes ofuscadas, y reportar la eficacia como tasa de detección junto a la tasa de falsos positivos

**Fuera de Alcance (v1):**
Panel centralizado tipo control-plane que administre múltiples VPS. La versión inicial asume una instalación por servidor.

**Modelo de adversario.**
Delimitar contra *quién* protege el sistema es lo que hace evaluable la afirmación de que protege. Se contempla un atacante que:

* opera desde internet, sin acceso al servidor ni a la base de datos;
* conoce las clases de ataque de uso corriente (inyección SQL, XSS, recorrido de rutas, inyección de comandos) y sabe que hay un filtro delante, por lo que aplica técnicas de ofuscación conocidas —codificación porcentual múltiple, escapes `\uXXXX` de JSON, entidades HTML, comentarios intercalados— para atravesarlo;
* no dispone de las firmas concretas en uso ni de una vulnerabilidad no publicada en las tecnologías de base.

Quedan **fuera** del modelo: el atacante con acceso al host o a PostgreSQL, el ataque volumétrico de denegación de servicio a nivel de red —que se absorbe aguas arriba, no en el origen—, el abuso por parte de un usuario legítimo ya autenticado, y el compromiso de la aplicación protegida por una vía que no atraviesa el proxy.

**Sobre de inspección.**
Lo que el sistema mira, y lo que explícitamente no:

| Se inspecciona | No se inspecciona |
|---|---|
| Ruta, cadena de consulta y cabeceras, salvo las excluidas por decisión explícita | Las respuestas del backend |
| El cuerpo de la petición hasta `OS_MAX_BODY_INSPECT_BYTES` | El cuerpo por encima de `client_body_buffer_size`, que Nginx vuelca a disco: llega marcado como truncado y **no se relee en la ruta de la petición** |
| Cada campo en crudo y normalizado (§ RF-03) | El tráfico que no atraviesa el proxy |

La terminación TLS puede resolverse en el borde del proveedor de despliegue; en esa topología el proxy recibe la conexión ya descifrada y el requisito RF-04 se satisface fuera del contenedor.

---

### 3. Arquitectura del Sistema

#### 3.1 Visión General

"El proxy inverso es el único punto de entrada del tráfico web. Cada petición pasa por dos planos separados: el plano de datos (la petición HTTP en sí, que debe llegar al backend con la menor latencia posible) y el plano de control (la decisión de si esa petición se permite, y el registro de esa decisión)."

**Componentes Principales:**

| Componente | Responsabilidad | Naturaleza |
|---|---|---|
| Nginx / OpenResty | Recibe tráfico, termina TLS, delega decisión al motor vía Lua | Configuración + script delgado |
| Motor de reglas (Go) | Evalúa peticiones, aplica rate limiting, escribe log de auditoría | Código propio — núcleo del sistema |
| Dashboard API (Go) | Expone REST + WebSocket para panel de administración | Código propio |
| Dashboard Web (React) | Interfaz de monitoreo en tiempo real | Código propio |
| Redis | Estado en tiempo real y pub/sub de eventos | Infraestructura de terceros |
| PostgreSQL / SQLite | Persistencia del log de auditoría con integridad verificable | Infraestructura de terceros + esquema propio |

#### 3.2 Flujo de una Petición

Toda petición HTTP entrante sigue esta secuencia, identificada por correlation ID único:

1. El cliente conecta contra Nginx/OpenResty, que termina TLS y genera un request_id (UUID)

2. Nginx invoca al motor de reglas mediante auth_request interno, enviando IP, headers, método, ruta y request_id

3. El motor de reglas evalúa la petición contra las reglas activas usando estado en Redis

4. El motor responde permitir o bloquear, escribiendo el evento en el log de auditoría y publicándolo en Redis Pub/Sub

5. Si es 'permitir', Nginx reenvía la petición al backend. Si es 'bloquear', Nginx corta la conexión

6. El dashboard recibe el evento en tiempo real vía Redis y actualiza la vista

#### 3.3 Modelo de Despliegue

"Cada instalación es autocontenida: un VPS ejecuta un único stack (proxy, motor, dashboard, Redis, base de datos) levantado con Docker Compose. No existe una instancia central que administre múltiples VPS — cada despliegue es independiente."

El backend protegido puede estar escrito en cualquier tecnología siempre que exponga un puerto HTTP/HTTPS accesible desde la red del stack.

---

### 4. Decisiones Tecnológicas

#### 4.1 Motor de Proxy

| Opción | A Favor | En Contra |
|---|---|---|
| **Nginx / OpenResty ✓** | Liviano, maduro, altísima adopción, soporte nativo de Lua | Configuración menos flexible que proxy 100% programable |
| HAProxy | Excelente para balanceo de carga de alto rendimiento | Menor ecosistema para lógica embebida |
| Traefik | Enrutamiento dinámico cómodo en contenedores | Mayor sobrecarga para un VPS pequeño |

**Justificación:** "Nginx/OpenResty se elige porque permite mantener el proxy como una capa delgada (config + un script Lua que llama al motor de reglas) sin convertirlo en el lugar donde vive la lógica de negocio — esa lógica pertenece al motor de reglas en Go."

#### 4.2 Lenguaje del Motor de Reglas

| Opción | A Favor | En Contra |
|---|---|---|
| **Go ✓** | Alta concurrencia nativa (goroutines), binario único sin dependencias, bajo consumo de memoria | Ecosistema de librerías más chico para tareas generales |
| Node.js | Ecosistema enorme, mismo lenguaje que muchos backends | Modelo de concurrencia menos predecible bajo carga |
| Python | Rapidez de desarrollo, buenas librerías de análisis | Rendimiento insuficiente para camino crítico |

#### 4.3 Frontend del Dashboard

| Opción | A Favor | En Contra |
|---|---|---|
| **React ✓** | Ecosistema maduro, componentes de datos, curva conocida | Requiere paso de build empaquetado en contenedor |
| Svelte | Bundle más liviano | Ecosistema de componentes de dashboard reducido |
| HTMX + templates Go | Cero build de frontend | Peor ajuste para UI altamente interactiva |

#### 4.4 Comunicación Proxy ↔ Motor de Reglas

| Opción | A Favor | En Contra |
|---|---|---|
| **Lua + auth_request ✓** | Nativo de Nginx/OpenResty, sub-request interno de bajo overhead | Lógica de glue en dos lenguajes |
| Sidecar HTTP puro | Más simple de razonar | Overhead de red por cada petición |

#### 4.5 Bus de Eventos en Tiempo Real

| Opción | A Favor | En Contra |
|---|---|---|
| **Redis Pub/Sub ✓** | Ya se necesita Redis para rate limiting; latencia mínima | Sin persistencia de eventos |
| Kafka | Alta capacidad de retención y replay | Sobreingeniería para un solo VPS |
| NATS | Muy liviano | Infraestructura adicional sin beneficio claro |

#### 4.6 Almacenamiento del Log de Auditoría

| Opción | A Favor | En Contra |
|---|---|---|
| **PostgreSQL / SQLite ✓** | Consultas estructuradas, transacciones para cadena de hashes | Requiere gestión de esquema y migraciones |
| Archivos planos | Simplicidad extrema | Sin garantías transaccionales |

#### 4.7 Modelo de Empaquetado

| Opción | A Favor | En Contra |
|---|---|---|
| **Docker Compose multi-contenedor ✓** | Un solo comando de instalación, cada servicio se actualiza independientemente | Ligeramente más piezas que administrar |
| Contenedor único monolítico | Instalación aparentemente más simple | Un fallo tumba todo |

---

### 5. Patrones de Diseño Aplicados

#### 5.1 Sidecar / Chain of Responsibility

"El proxy no decide, delega. Cada petición pasa por una cadena de responsabilidad: Nginx → motor de reglas → (permitir/bloquear). Cada eslabón tiene una única responsabilidad y puede evolucionar o desplegarse de forma independiente — es la misma idea detrás del patrón Sidecar en arquitecturas de microservicios."

#### 5.2 Strategy — Reglas de Filtrado Intercambiables

"Cada regla (detección de SQLi, límite de tasa, lista de bloqueo por IP) se modela como una implementación de una misma interfaz. El motor de reglas no conoce los detalles de cada regla, solo las ejecuta en secuencia — así se pueden agregar o quitar reglas sin tocar el núcleo del motor."

```go
type Rule interface {
    Name() string
    Evaluate(ctx context.Context, req *RequestContext) (Verdict, string)
}

// El motor solo conoce la interfaz, no las reglas concretas
func (e *Engine) Decide(req *RequestContext) Decision {
    for _, rule := range e.rules {
        if v, reason := rule.Evaluate(e.ctx, req); v == Block {
            return Decision{Verdict: Block, Rule: rule.Name(), Reason: reason}
        }
    }
    return Decision{Verdict: Allow}
}
```

#### 5.3 Repository — Acceso al Log de Auditoría

"El motor de reglas nunca escribe SQL directamente contra Postgres/SQLite. Habla contra una interfaz AuditRepository, lo que permite cambiar el motor de base de datos (SQLite en una instalación pequeña, Postgres en una con más volumen) sin tocar la lógica de negocio."

```go
type AuditRepository interface {
    Append(ctx context.Context, entry AuditEntry) error
    VerifyChain(ctx context.Context, from, to time.Time) (bool, error)
}
```

#### 5.4 Observer / Pub-Sub — Eventos hacia el Dashboard

"El motor de reglas publica cada decisión en un canal de Redis; no conoce ni le importa quién está escuchando. El backend del dashboard se suscribe a ese canal y reenvía los eventos por WebSocket a los clientes conectados. Esto desacopla por completo el motor del dashboard: uno puede caerse sin afectar al otro."

#### 5.5 Configuración 12-factor

"Toda la configuración (puertos, credenciales de Redis/DB, reglas iniciales, dominio del backend protegido) se inyecta por variables de entorno, nunca hardcodeada ni editada a mano en archivos dentro del contenedor."

---

### 6. Trazabilidad Forense

"El log de auditoría no es una herramienta de debug: se diseña para servir como evidencia. Cada entrada incluye el hash de la entrada anterior, de forma que cualquier alteración o eliminación de un registro intermedio rompe la cadena y queda expuesta al verificarla."

#### 6.1 Qué Se Registra

* Tráfico externo: IP de origen, headers relevantes, método, ruta, geo-IP, regla que disparó el veredicto, latencia por etapa
* Eventos internos del sistema: cambios de configuración, reinicio de servicios, alta o baja de reglas
* Acceso administrativo: quién entra al dashboard, qué configuración modifica y cuándo

#### 6.2 Cadena de Integridad

```go
type AuditEntry struct {
    ID        string    // UUID de la entrada
    RequestID string    // correlaciona con la petición HTTP original
    Timestamp time.Time
    Kind      string    // "traffic" | "system" | "admin"
    Payload   map[string]any
    PrevHash  string    // hash de la entrada anterior en la cadena
    Hash      string    // sha256(PrevHash + Payload + Timestamp)
}

func (e AuditEntry) ComputeHash() string {
    raw := e.PrevHash + e.Timestamp.String() + fmt.Sprint(e.Payload)
    sum := sha256.Sum256([]byte(raw))
    return hex.EncodeToString(sum[:])
}
```

"Verificar la integridad del histórico consiste en recorrer la cadena y recalcular cada hash: si alguno no coincide con el registrado, se identifica el punto exacto de manipulación."

#### 6.3 Separación de Logs

| Log | Propósito | Retención |
|---|---|---|
| Operativo | Debug rápido, formato JSON estructurado | Rotación corta (p. ej. 30 días) |
| Auditoría / forense | Evidencia con cadena de integridad verificable | Retención larga, append-only |
| Acceso administrativo | Quién y qué cambió en el propio sistema | Retención larga, junto al log de auditoría |

---

### 7. Estructura del Repositorio

**Monorepo:** "el proxy, el motor y el dashboard evolucionan y versionan juntos."

```
open-shield/
├── proxy/                      # config Nginx/OpenResty + scripts Lua
├── engine/                     # motor de reglas y decisión (Go)
│   ├── cmd/
│   ├── internal/rules/         # implementaciones de Rule (Strategy)
│   ├── internal/ratelimit/
│   └── internal/audit/         # AuditRepository, hash chaining
├── dashboard/
│   ├── api/                    # backend del dashboard (Go)
│   └── web/                    # frontend React
├── deploy/
│   ├── docker-compose.yml
│   ├── docker-compose.quickstart.yml
│   └── .env.example
├── migrations/                 # esquema de Postgres/SQLite
└── docs/
```

#### 7.1 docker-compose.yml (esqueleto)

```yaml
services:
  proxy:
    build: ./proxy
    ports: ["80:80", "443:443"]
    depends_on: [engine]
  engine:
    build: ./engine
    env_file: .env
    depends_on: [redis, db]
  dashboard-api:
    build: ./dashboard/api
    env_file: .env
    depends_on: [redis, db]
  redis:
    image: redis:7-alpine
  db:
    image: postgres:16-alpine
    env_file: .env
    volumes: ["db-data:/var/lib/postgresql/data"]
volumes:
  db-data:
```

#### 7.2 Hook Nginx/OpenResty → Motor de Reglas

```nginx
location / {
    auth_request /__decide;
    proxy_pass   http://backend;
}

location = /__decide {
    internal;
    proxy_pass http://engine:8080/decide;
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Real-IP      $remote_addr;
    proxy_set_header X-Request-ID   $request_id;
}
```

#### 7.3 Hook de Eventos en Vivo — React

```javascript
function useLiveEvents() {
  const [events, setEvents] = useState([]);
  useEffect(() => {
    const ws = new WebSocket(WS_URL + "/live");
    ws.onmessage = (msg) => {
      const ev = JSON.parse(msg.data);
      setEvents((prev) => [ev, ...prev].slice(0, 200));
    };
    return () => ws.close();
  }, []);
  return events;
}
```

---

### 8. Requerimientos

#### 8.1 Funcionales

| ID | Descripción |
|---|---|
| RF-01 | Interceptar toda conexión entrante antes de que llegue al servidor de origen |
| RF-02 | Enrutar hacia distintos backends internos según configuración |
| RF-03 | Filtrar solicitudes según patrones definidos, sobre la entrada **normalizada**. Clases cubiertas, lista cerrada para esta versión: inyección SQL, XSS, recorrido de rutas/LFI e inyección de comandos |
| RF-03.1 | Normalizar cada campo antes de comparar: decodificación porcentual hasta punto fijo (acotada), escapes `\uXXXX` de JSON, entidades HTML y eliminación de bytes nulos y caracteres de control. Se conserva además la comparación sobre la forma cruda, porque normalizar también puede destruir una coincidencia |
| RF-04 | Soportar terminación y renovación automática de certificados TLS/SSL, o delegarla en el borde del proveedor cuando el despliegue lo resuelva ahí |
| RF-05 | Limitar peticiones por IP en una ventana de tiempo (rate limiting), con presupuesto adicional por recurso para los puntos sensibles a fuerza bruta. El presupuesto por IP subsiste **por encima** del específico: repartir la carga entre rutas no debe multiplicar el presupuesto total |
| RF-06 | Registrar cada conexión con IP, resultado y motivo, con integridad verificable |
| RF-07 | Notificar al personal técnico ante patrones de tráfico anómalos |
| RF-08 | Soportar balanceo de carga entre instancias de un mismo servicio |
| RF-09 | Exponer un dashboard en tiempo real con el estado del tráfico filtrado |
| RF-10 | Permitir instalación completa mediante un único comando (Docker Compose) |
| RF-11 | **(propuesta)** Bloquear automáticamente, y de forma temporal, la dirección que acumule un número configurable de decisiones de bloqueo dentro de una ventana |

**Sobre RF-11.** Es la única incorporación de la v1.2 que amplía el alcance en lugar de precisar lo ya acordado, por lo que se enuncia aparte en vez de derivarse de RF-05. Hasta aquí el sistema decide petición a petición y la respuesta sobre direcciones es manual; un lazo automático de detección a respuesta introduce estado que modifica la política **sin intervención humana**, y con él dos riesgos que no existían:

* **Denegación de servicio autoinfligida.** Un falso positivo deja de costar una petición rechazada y pasa a expulsar a una dirección legítima durante todo el tiempo de vida del bloqueo. El criterio de activación debe fijarse a partir de la tasa de falsos positivos medida, no por intuición, y el bloqueo debe caducar solo.
* **Bloqueo inducido de terceros.** Si la cabecera de la que se extrae la dirección real fuese falsificable por el cliente, un atacante podría provocar el bloqueo de direcciones ajenas. La función exige, como precondición, que la dirección provenga de una cabecera que un borde de confianza sobrescriba y que el cliente no pueda extender.

Delimitación de RF-11: actúa sobre direcciones IP, no sobre sesiones ni cuentas; el bloqueo es siempre temporal; y no contempla reputación compartida ni fuentes externas de inteligencia.

#### 8.2 No Funcionales

| Categoría | Criterio |
|---|---|
| Seguridad | Cifrado en tránsito, mínimo privilegio, actualización periódica de reglas |
| Resistencia a evasión | La eficacia se mide sobre un corpus que incluye, para cada vector, sus variantes ofuscadas según el modelo de adversario de §2. Se reportan tasa de detección y tasa de falsos positivos; una cifra de detección sin la de falsos positivos no constituye una medición |
| Disponibilidad | Operación 24/7, tolerancia a fallos, objetivo ≥99% |
| Rendimiento | Latencia adicional del proxy < 50 ms bajo carga normal |
| Escalabilidad | Alta de nuevos backends sin interrumpir el servicio |
| Mantenibilidad | Configuración por variables de entorno, apta para CI/CD |
| Trazabilidad forense | Log de auditoría con cadena de integridad verificable |
| Portabilidad | Instalación equivalente en cualquier VPS, sin dependencia del stack protegido |

#### 8.3 Requerimientos Técnicos

| Ámbito | Detalle |
|---|---|
| Hardware | Servidor físico o virtual; CPU/RAM según tráfico esperado; almacenamiento para logs y certificados |
| Software | Linux, Nginx/OpenResty, Go (motor + dashboard API), React, Redis, PostgreSQL/SQLite, Certbot |
| Red | IP pública, DNS hacia el proxy, puertos 80/443, firewall perimetral complementario |
| Despliegue | Docker Compose; instalación agnóstica al stack del backend protegido |

#### 8.4 Requerimientos No Técnicos

* Personal capacitado en administración de sistemas Linux y redes
* Políticas de seguridad de la información y gestión de incidentes
* Capacitación del personal técnico en la operación del sistema
* Documentación técnica y manual de operación
* Aprobación de la gerencia de TI y coordinación de la ventana de migración
* Plan de reversión (rollback) ante afectación de disponibilidad

---

### 9. Viabilidad

| Dimensión | Evaluación |
|---|---|
| Técnica | Tecnologías open source, maduras y documentadas; no exige modificar las aplicaciones existentes |
| Operativa | Bajo impacto en el personal actual; curva de aprendizaje moderada con capacitación |
| Económica | Sin costo de licenciamiento; inversión principal en horas de implementación |

---

### 10. Cronograma Tentativo

| Fase | Semanas | Entregable |
|---|---|---|
| Levantamiento y diagnóstico | 1–2 | Diagnóstico de exposición de la infraestructura a proteger |
| Selección tecnológica y diseño | 3 | Arquitectura y decisiones documentadas |
| Implementación en pruebas | 4–6 | Proxy, motor de reglas y dashboard funcionales |
| Pruebas de seguridad y carga | 7–8 | Reporte de simulacros de ataque y rendimiento |
| Migración a producción | 9 | Stack operando como punto único de entrada |
| Documentación y capacitación | 10 | Manual de operación y personal capacitado |

---

### 11. Conclusiones

"El proyecto se sostiene sobre una separación clara entre lo que es configuración de terceros (Nginx, Redis, Postgres) y lo que es desarrollo propio y defendible: el motor de reglas en Go, el dashboard en React, y el esquema de trazabilidad forense con integridad verificable. Esa separación es también lo que mantiene al sistema desacoplado de cualquier infraestructura concreta — el mismo stack, empaquetado en Docker Compose, se instala igual en cualquier VPS y puede incorporarse a un pipeline de CI/CD sin costo ni pasos manuales."
