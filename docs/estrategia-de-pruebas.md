# Estrategia de pruebas

Este documento describe la batería de pruebas de open-shield: qué niveles hay,
qué garantiza cada uno, cómo ejecutarlos y cómo bloquean la fusión de un pull
request.

El §2 del documento técnico fija como tercer objetivo *"validar el sistema
mediante pruebas de carga y simulacros de ataque controlados"*, y el §8.2 pone
números a ello: menos de **50 ms** de latencia añadida y una disponibilidad
**≥ 99 %**. Este módulo convierte esas dos frases en algo que puede fallar una
compilación.

---

## 1. Los niveles

| Nivel | Dónde vive | Qué garantiza | Dependencias | Duración |
|---|---|---|---|---|
| **Unitario** | junto al código, `*_test.go` | invariantes de la cadena de hashes, reglas de detección, parseo, capas HTTP con dobles | ninguna | < 5 s |
| **Fuzzing** | `internal/model/fuzz_test.go` | que el hash sobrevive a cualquier entrada, no solo a las que se le ocurrieron a alguien | ninguna | semillas en el gate; 5 min por objetivo de noche |
| **Integración** | `test/integration/` y junto a los paquetes `internal` | el SQL real, las migraciones, la ventana deslizante en Redis real, Pub/Sub | PostgreSQL + Redis | ~10 s |
| **End-to-end** | `test/e2e/` | el camino completo: proxy → motor → log → dashboard | el stack en Docker | ~10 s |
| **Carga y estrés** | `test/load/k6/` | el presupuesto del §8.2, traducido a umbrales de k6 | el stack en Docker | 1 min / 9 min / 30 min |
| **Frontend** | `dashboard/web/src/**/*.test.tsx` | el feed en vivo, el cliente de la API, la tabla forense | Node | ~6 s |

### La pirámide, en una línea

Lo barato y sin dependencias corre siempre; lo caro corre una vez por PR; lo
lento corre de noche. Nada se ejecuta a mano por convención.

---

## 2. El corpus compartido

`test/corpus/` contiene dos ficheros JSON:

- **`attacks.json`** — 17 vectores de SQLi y XSS, cada uno con la regla y la
  firma que *debe* dispararse.
- **`benign.json`** — 15 peticiones legítimas que se parecen a un ataque y que
  **no** deben bloquearse.

Los consumen tres niveles distintos:

```
test/corpus/*.json
   ├──► engine/internal/rules/corpus_test.go   la cadena de reglas, aislada
   ├──► test/e2e/                              el stack vivo, a través del proxy
   └──► test/load/k6/main.js                   el escenario "attack" bajo carga
```

Añadir un vector es editar un JSON, y queda cubierto en los tres sitios a la
vez. No hay forma de que uno de los tres se quede atrás.

### Por qué el corpus benigno importa tanto como el de ataques

El presupuesto de falsos positivos es **cero**. Un filtro que bloquea a
`O'Brien` al iniciar sesión, o un artículo sobre la Unión Europea, lo acaba
desactivando el operador — y entonces no detecta nada en absoluto. Varios casos
de `benign.json` son adversarios a propósito: contienen las mismas palabras que
buscan las firmas, en contextos donde son inofensivas.

### Cómo añadir un vector

1. Añade el caso a `test/corpus/attacks.json`:

   ```json
   {
     "id": "sqli_nombre_descriptivo",
     "description": "Qué es, en texto legible",
     "rule": "sqli",
     "signature": "union_select",
     "method": "GET",
     "path": "/buscar",
     "query": "q=x%27%20UNION%20SELECT..."
   }
   ```

2. `query` se escribe **tal como viaja por el cable**, percent-encoded. Es lo
   que Nginx entrega al motor y lo que un cliente HTTP transmitirá sin tocar.
   Varios vectores solo son detectables después de que el motor decodifica el
   campo, y eso es deliberado: ejercita la pasada de decodificación de
   `scanTargets`.

3. `signature` fija **qué firma concreta** debe dispararse. Las firmas se
   evalúan en el orden del fichero por cada campo, así que un caso tiene que
   estar escrito para alcanzar la suya y no una anterior. Si empieza a coincidir
   con otra, el test falla — y eso es correcto: es un cambio real en lo que el
   log dirá sobre ese ataque.

4. Ejecuta `make test`. Si falla con *"blocked by X, want Y"*, el payload está
   activando una firma anterior; ajústalo hasta que solo active la suya.

5. Si el vector se parece a tráfico real, añade también el caso legítimo
   equivalente a `benign.json`.

> **Trampa observada.** Un caso con
> `url=javascript%3Aalert(document.cookie)` no dispara `javascript_uri` sino
> `cookie_theft`: `document.cookie` aparece sin codificar en el campo **crudo**,
> y el crudo se escanea antes que el decodificado. Mantén cada vector limpio de
> cualquier otro payload.

---

## 3. Ejecutar cada nivel

Go no hace falta en la máquina: todo corre en contenedores.

```bash
make test              # unitarios + go vet. Sin dependencias. Segundos.
make test-race         # lo mismo con el detector de carreras.
make lint              # gofmt, go vet y golangci-lint.
make vuln              # CVEs conocidos en las dependencias.

make test-integration  # levanta PostgreSQL y Redis efímeros, corre, y los baja.
make cover             # cobertura por paquete contra test/coverage-floors.txt.

make up-e2e                                  # el stack con los ajustes del E2E
OS_ADMIN_PASSWORD='...' make test-e2e        # el camino completo

make up-load           # el stack con los ajustes de carga
make test-load         # k6, perfil corto (~1 min)
make test-load-full    # k6, perfil completo (~9 min)
make test-soak         # k6, resistencia (30 min)

make test-web          # tipos y tests del dashboard React

make test-all          # todo lo que no necesita el stack levantado
```

### Los tests de integración se saltan solos

Sin `OS_TEST_POSTGRES_DSN` y `OS_TEST_REDIS_ADDR` definidas, toda la batería de
integración se salta con un mensaje que dice cómo levantar las dependencias.
Nunca falla en una máquina que simplemente no las tiene corriendo.

`make test-integration` las levanta con `deploy/docker-compose.test.yml`, en
puertos altos (55432 y 56379) para que una corrida de tests no choque con un
stack de demostración que alguien dejó encendido.

### Por qué `-p 1` en integración

La batería está repartida en tres directorios porque la regla `internal` de Go
lo obliga: solo código bajo `engine/` puede importar `engine/internal/…`, y solo
código bajo `dashboard/api/` puede importar `dashboard/api/internal/…`. Los tres
comparten una única base de datos. Sin `-p 1`, los binarios de test corren en
paralelo y se vacían las tablas unos a otros a mitad de ejecución; los fallos
resultantes no tienen ningún sentido. Los helpers compartidos viven en
`test/harness/`.

---

## 4. Qué comprueba cada nivel, en concreto

### 4.1 Unitario — el núcleo forense

`internal/model` e `internal/audit` son el aporte central del proyecto, y sus
tests son la protección de esa afirmación:

- El hash es **determinista** sobre 1 000 recálculos, independiente del orden de
  iteración del mapa, de la zona horaria y de un viaje de ida y vuelta por JSON.
- Los campos van **prefijados con su longitud**: ninguna repartición distinta de
  los mismos bytes produce el mismo digest. Un objetivo de fuzzing lo comprueba
  contra todas las divisiones posibles de cada entrada generada.
- El escritor es **uno solo**: 1 000 goroutines llamando a `Record` producen una
  cadena estrictamente lineal bajo `-race`. Dos escritores sellando contra la
  misma cabeza la bifurcarían, y la verificación reportaría manipulación donde
  no la hubo.
- Con la cola llena se **descarta y se cuenta**, nunca se bloquea. El §8.2
  presupuesta menos de 50 ms de latencia añadida; bloquear una petición por
  escribir el log convertiría un atasco de auditoría en una caída del sitio.
- Una escritura rechazada **no avanza la cabeza**: la siguiente entrada enlaza
  con la última que realmente entró.

### 4.2 Unitario — el contrato con el hook Lua

`engine/internal/httpapi` es la frontera entre `proxy/lua/openshield.lua` y el
motor, y no hay nada más en el camino de la petición. Sus tests fijan la forma
del veredicto, el eco del `X-Request-ID`, los límites de tamaño y — sobre todo —
la **invariante negativa**: el payload auditado nunca contiene el cuerpo de la
petición, ni la cabecera `Cookie`, ni `Authorization`.

### 4.3 Integración — lo que solo existe con una base de datos delante

- **Paridad entre almacenes**: las mismas escrituras deben producir entradas que
  vuelven a hashear correctamente tanto en memoria como en PostgreSQL. Es lo que
  demuestra que el truncado a microsegundos y `NormalizePayload` sobreviven al
  viaje por `timestamptz` y `jsonb`.
- **Detección de manipulación a nivel de fila**: un `UPDATE`, un `DELETE` en
  medio y una entrada resellada. Los tres se detectan y la verificación nombra
  la entrada exacta. Es `scripts/tamper-demo.sh` convertido en test.
- **El trigger de solo-anexado**: la base de datos rechaza `UPDATE`, `DELETE` y
  `TRUNCATE` sobre `audit_log`. La cadena hace la manipulación *detectable*; el
  trigger la hace incómoda.
- **Migraciones**: idempotentes, en orden de nombre, transaccionales, y
  serializadas por el lock de aviso cuando dos contenedores arrancan a la vez.
- **El orden de la cadena es `seq`, no `ts`**: 25 entradas compartiendo el mismo
  instante verifican correctamente.

### 4.4 End-to-end — el bucle de evidencia

El test que justifica el proyecto entero:

```
ataque → 403 con X-Request-ID
       → GET /api/v1/events?request_id=…
       → la entrada nombra la regla, la IP y el fragmento que disparó
       → GET /api/v1/audit/verify sigue en ok:true
```

RF-03 y RF-06 juntos. Junto a él:

- **Lo que no se persiste**: un `POST` con `Cookie`, `Authorization` y
  contraseña en el cuerpo; ninguno de los tres aparece en el evento registrado.
- **El contrato del Lua**: que el evento traiga `ip`, `method`, `path` y `host`
  poblados demuestra que `openshield.lua` los rellena. El script Lua no tiene
  tests propios; se cubre por aquí (ver §7).
- **RF-05**: una ráfaga desde una IP produce 429.

### 4.5 Carga — el §8.2, ejecutable

`test/load/k6/main.js` corre cuatro escenarios **en secuencia**, no en paralelo:

| Escenario | Contra | Para qué |
|---|---|---|
| `baseline` | `demo-backend` directo | la referencia |
| `proxied` | el proxy, tráfico legítimo | la resta con `baseline` es la sobrecarga real |
| `attack` | el proxy, corpus de ataques | que el filtrado sigue funcionando bajo carga |
| `mixed` | el proxy, 95 % legítimo / 5 % ataque | la forma del tráfico real |

Corren en secuencia porque en paralelo competirían por la misma CPU y la
diferencia mediría la contención, no el sistema.

Los umbrales (`test/load/k6/thresholds.js`) hacen que k6 salga con código ≠ 0:

```js
'http_req_duration{scenario:proxied}': ['p(95)<50'],   // §8.2: < 50 ms
'http_req_failed{scenario:proxied}':   ['rate<0.01'],  // §8.2: ≥ 99 %
'checks{scenario:attack}':             ['rate>0.99'],  // RF-03
```

El último es el que más importa y el más fácil de olvidar: un proxy que se
volviera rápido saltándose la cadena de reglas bajo presión pasaría todos los
umbrales de latencia.

Al terminar, el resumen imprime la comparación:

```
                                p50          p95
Backend directo               0.48 ms     1.04 ms
A través del proxy            2.01 ms     7.60 ms
----------------------------------------------------
Sobrecarga añadida            1.52 ms     6.56 ms
```

Compárala con la tabla del §5.1 del manual de operación.

> **Por qué la carga necesita su propio override.** El motor identifica al
> cliente por `ngx.var.remote_addr` (`proxy/lua/openshield.lua:141`), no por
> `X-Forwarded-For` — una cabecera que controla el cliente no sirve para
> contar. Todos los usuarios virtuales de k6 salen de una sola dirección y
> comparten un único cubo: con el límite por defecto la corrida se
> auto-estrangularía en el primer segundo, y el resultado mediría el rate
> limiter. `deploy/docker-compose.load.yml` lo desactiva de hecho. **RF-05 no se
> cubre ahí**: se cubre en E2E y en `smoke.sh`, contra un límite real.

### 4.6 Frontend

- `useLiveEvents`: reconexión con backoff exponencial, tope de 200 eventos,
  supervivencia a un frame malformado, y limpieza al desmontar. Un feed que no
  reconecta se queda en silencio, y el silencio es indistinguible de "no hay
  tráfico" — el peor fallo posible en una herramienta de monitorización.
- `api.ts`: la cookie de sesión viaja en cada petición, un 4xx llega al llamante
  como error con el mensaje de la API, y el 204 del borrado no se intenta
  parsear como JSON.
- `EventTable`: los payloads controlados por el atacante se renderizan **como
  texto, nunca como marcado**. Es el test que se dará cuenta el día que alguien
  alcance `dangerouslySetInnerHTML`.

---

## 5. Cobertura

`scripts/coverage.sh` mide cobertura de sentencias **por paquete** y la contrasta
con los mínimos de `test/coverage-floors.txt`.

Por paquete y no un número global: un total único deja que un paquete grande y
bien cubierto tape a uno pequeño y sin probar. Los mínimos tampoco son
uniformes — el núcleo forense y el camino de la petición se exigen alto porque
un hueco ahí es un hueco en lo que el proyecto afirma hacer; el pegamento se
exige bajo porque perseguir sus últimas sentencias no compra nada.

Los mínimos están **medidos**, no aspirados: cada uno queda unos puntos por
debajo de lo que la batería alcanza de verdad. Un umbral que nace en rojo se
desactiva en una semana, y entonces no protege nada.

La cobertura se mide **con las dependencias levantadas**, en el job de
integración. Medirla sin ellas dejaría `internal/audit` en aproximadamente la
mitad de su cifra real: su almacén SQL es la mayor parte del fichero.

Para subir un mínimo: `make cover`, toma el valor medido, réstale unos puntos.
Para bajarlo: explica por qué en el mensaje del commit.

---

## 6. El gate de CI

`.github/workflows/ci.yml` corre en cada pull request. **Los seis checks son
obligatorios.**

| Check | Qué hace | Duración aprox. |
|---|---|---|
| `lint` | `gofmt`, `go vet`, `golangci-lint` | ~1 min |
| `unit` | toda la batería, y otra vez con `-race` | ~2 min |
| `vuln` | `govulncheck` sobre dependencias y toolchain | ~1 min |
| `integration` | PostgreSQL y Redis reales + los mínimos de cobertura | ~3 min |
| `web` | tipos, tests y build del dashboard | ~2 min |
| `stack` | contenedores reales: E2E, humo, carga corta y demo de manipulación | ~8 min |

`.github/workflows/nightly.yml` corre de madrugada y a demanda: fuzzing de 5
minutos por objetivo, carga completa, resistencia de 30 minutos, integración con
el detector de carreras, y verificación de la cadena sobre 200 000 entradas.

### Los jobs de Go llaman a los mismos targets del Makefile

Con `GO_RUN=` vacío, `$(GO_RUN) sh -c "…"` se degrada a ejecución nativa contra
`actions/setup-go`. Un solo sitio define qué significa "los tests pasan", y no
se desincroniza entre la máquina de quien desarrolla y el runner.

### El `.env` en CI

No hay `deploy/.env` en el repositorio y nunca debe haberlo. El job `stack` lo
genera con secretos desechables.

El hash bcrypt se obtiene con `-hash-password`, que **ya imprime la línea con
los `$` escapados como `$$`**. Compose lee un `$` suelto como referencia a una
variable, así que pegar el hash crudo entrega un valor **vacío** al contenedor,
sin ningún error, y todos los inicios de sesión fallan. El workflow comprueba el
escapado antes de gastar ocho minutos descubriéndolo en la pantalla de login.

### Hacer que los checks bloqueen de verdad

Un workflow no impide fusionar por sí solo. Hay que marcar los checks como
requeridos en la protección de la rama:

```bash
gh api -X PUT repos/MJoDev/open-shield/branches/main/protection \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["lint", "unit", "vuln", "integration", "web", "stack"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null
}
JSON
```

`strict: true` obliga además a que la rama esté actualizada con `main` antes de
fusionar, que es lo que evita que dos PRs verdes por separado rompan `main`
juntos.

### Comprobar que el gate muerde

Un gate que nunca se ha visto fallar no está probado. Para comprobarlo:

```bash
# El presupuesto de latencia es sobreescribible precisamente para esto.
OS_LOAD_LATENCY_BUDGET_MS=3 make test-load   # sale con código 99
```

Para el resto, invierte un byte en `internal/model/audit.go` (`Seal`) en una
rama desechable y abre un PR de prueba: `unit` y `stack` deben ponerse en rojo.

---

## 7. Qué no se prueba, y por qué

- **El script Lua no tiene tests unitarios.** Montar un arnés de Lua (busted,
  `resty`) para 194 líneas que no contienen lógica de filtrado — recogen datos,
  preguntan y actúan sobre la respuesta — costaría más de lo que protege. Se
  cubre por E2E, que comprueba que los campos que rellena llegan poblados al log
  y que el modo `OS_FAIL_MODE=open` se respeta.
- **`engine/cmd/engine` y `dashboard/api/cmd/api` no tienen mínimo de
  cobertura.** Son cableado de proceso; un test unitario ahí solo afirmaría que
  `main()` llama a lo que llama `main()`. Los cubre el nivel end-to-end, que
  arranca los binarios de verdad.
- **Magnitudes numéricas extremas.** `encoding/json` escribe un float en
  notación exponencial en cuanto su exponente llega a 21 o baja de −6: `1e21` se
  serializa como `"1e+21"`, y `jsonb` devuelve `"1000000000000000000000"`. Los
  dos textos canonicalizan distinto, así que el hash recalculado al leer no
  coincide con el sellado y `VerifyChain` reporta manipulación sobre un log que
  nadie ha tocado. Ningún payload actual se acerca a ninguno de los dos umbrales
  (`decision_ms` son milisegundos de un dígito, `status` tres dígitos), y
  arreglarlo cambiaría lo que se hashea, invalidando toda cadena ya existente.
  Queda fijado como límite conocido en `TestExtremeMagnitudesAreOutsideTheChainsRange`
  y anotado en `decisiones-implementacion.md`.

---

## 8. Referencias

- `docs/technical-document.md` §2 (objetivos), §8.2 (requisitos no funcionales)
- `docs/decisiones-implementacion.md` — dónde y por qué el código se desvía
- `docs/manual-operacion.md` §5 — rendimiento medido en producción
- `test/coverage-floors.txt` — los mínimos, con el razonamiento de cada uno
