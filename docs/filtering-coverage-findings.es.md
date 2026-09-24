---
titulo: "Hallazgos de cobertura de filtrado y propuesta para el documento técnico v1.2"
proyecto: "open-shield"
fecha: "2026-09-19"
estado: "Registro de hallazgo. No se ha modificado código."
idioma: "es"
version_en: "filtering-coverage-findings.md"
---

# Hallazgos de cobertura de filtrado

Este documento registra el resultado de una evaluación de **resistencia a
evasión** de la cadena de reglas, realizada el 2026-09-19 sobre el motor tal
como está en `main`. No se ha modificado ni una línea de código: el objetivo es
fijar la evidencia y decidir después qué entra en la versión 1.2 del documento
técnico.

Se escribe aquí y no en `implementation-decisions.es.md` porque todavía no hay
ninguna divergencia entre documento y código que registrar. Cuando alguno de
los cambios propuestos se implemente, su entrada correspondiente va allí.

---

## 1. Motivación

El corpus de ataque (`test/corpus/attacks.json`) contiene 17 vectores para 16
firmas: aproximadamente uno por firma. Eso comprueba que **cada firma dispara
con su entrada canónica**, que es una propiedad necesaria pero distinta de la
que el sistema dice ofrecer.

El actor externo que el sistema pretende contener sabe que hay un filtro
delante. No envía el payload en claro. La pregunta sin responder era: ¿qué
ocurre cuando el mismo ataque llega ofuscado?

---

## 2. Método

Se construyó una sonda que instancia las reglas `sqli` y `xss` con las firmas
embebidas (`engine/internal/rules/patterns.json`) y las evalúa contra cuatro
familias:

- **A y B** — un ataque base de inyección SQL y sus variantes ofuscadas.
- **C** — un ataque base de XSS y sus variantes ofuscadas.
- **D** — clases de ataque para las que no existe firma.

Las variantes son técnicas de evasión documentadas y de uso corriente: doble
codificación porcentual, escapes `\uXXXX` de JSON y entidades HTML. El código
de la sonda está en el anexo y es reproducible con `go test`.

---

## 3. Resultados

**7 de 14 casos atraviesan el filtro.**

| Familia | Caso | Resultado | Firma que dispara |
|---|---|---|---|
| A | `admin'--` en `x-www-form-urlencoded` | Bloquea | `comment_terminator` |
| A | el mismo ataque con escape JSON `'` | **Evade** | — |
| A | el mismo ataque con comilla literal en JSON | Bloquea | `comment_terminator` |
| B | tautología `' OR 1=1--` en query | Bloquea | `quoted_tautology` |
| B | la misma con doble codificación | **Evade** | — |
| B | la misma con escape JSON | Bloquea | `bare_tautology` |
| C | `<script>` en query | Bloquea | `script_tag` |
| C | el mismo con doble codificación | **Evade** | — |
| C | el mismo con entidades HTML | **Evade** | — |
| C | el mismo con escape JSON | **Evade** | — |
| D | path traversal `../../etc/passwd` | **Evade** | sin firma |
| D | path traversal codificado | **Evade** | sin firma |
| D | inyección de comandos `;cat /etc/passwd` | **Evade** | sin firma |
| D | LFI por wrapper `php://filter` | **Evade** | sin firma |

### 3.1 Causas raíz

**(a) La normalización es de una sola pasada.** `scanTargets`
(`engine/internal/rules/patterns.go:132`) escanea cada campo en crudo y una vez
decodificado con `url.QueryUnescape`. La decisión está bien razonada y su
comentario la justifica correctamente, pero sólo cubre una capa: `%2527`
decodifica a `%27`, no a `'`, y ninguna de las dos formas casa con una firma.
Tampoco se contemplan los escapes `\uXXXX` de JSON ni las entidades HTML.

**(b) Las firmas de XSS están ancladas a caracteres literales.** Las ocho
dependen de un `<` o de un `:` presente en el texto. Cualquier representación
alternativa de esos caracteres las neutraliza por completo. Es la familia más
frágil de las dos: evaden 3 de 4 variantes, frente a 1 de 3 en SQLi.

**(c) Tres clases de ataque no tienen firma.** RF-03 enuncia "SQLi, XSS,
**payloads conocidos**". La tercera categoría está declarada y sin implementar.

### 3.2 Un resultado que conviene no pasar por alto

El caso B con escape JSON **sí** se bloquea, pero no por la firma que le
correspondía: `quoted_tautology` falla porque la comilla está ofuscada, y lo
atrapa `bare_tautology`, que no depende de ella.

Es decir: **la resistencia observada en ese caso no vino del diseño, vino de la
redundancia accidental entre dos firmas.** Confiar en eso no es una estrategia.
El hallazgo justifica con evidencia propia el principio de diseño que debe
adoptar la v1.2: *normalizar la entrada antes de comparar, en lugar de acumular
firmas que cubran cada representación*. Acumular firmas multiplica el coste por
petición y la superficie de falsos positivos; normalizar es una función acotada
en un único punto del código.

---

## 4. Impacto sobre objetivo, alcance y delimitación

La pregunta es si alguno de los cambios amplía lo acordado en el documento
técnico. La respuesta corta: **el objetivo no cambia; el alcance cambia en
un solo punto; la delimitación se vuelve más precisa, que es una mejora.**

| Cambio propuesto | Clasificación | ¿Altera el alcance? |
|---|---|---|
| Normalización multicapa | Corrección de defecto | **No.** RF-03 ya exige filtrar según patrones; si el patrón no ve el payload, el requisito no se cumple. Normalizar hace cumplir lo ya escrito |
| Clases de ataque ausentes | Completar requisito sub-implementado | **No**, pero obliga a cerrar la lista de "payloads conocidos" (ver §5) |
| Corpus de evasión | Metodología de validación | **No.** Cambia la estrategia de pruebas, no el sistema |
| RF-07 notificación | Requisito declarado y no implementado | **No.** Reduce la brecha entre documento y código |
| Rate limit por endpoint | Refinamiento de RF-05 | **No**, pero exige fijar una decisión de diseño (ver §5) |
| **Bloqueo automático progresivo** | **Capacidad nueva** | **Sí.** Requiere un RF nuevo |

### 4.1 El único cambio que sí amplía el alcance

Hoy el sistema decide **petición a petición** y la respuesta sobre IPs
(`ip_rules`) es enteramente manual. Un lazo automático detección → respuesta
introduce tres cosas que el documento técnico no contempla:

1. Estado que persiste entre peticiones y **modifica la política sin
   intervención humana**.
2. Un riesgo nuevo: **denegación de servicio autoinfligida**. Un falso positivo
   deja de ser una petición rechazada y pasa a ser una IP legítima expulsada
   durante todo el TTL del bloqueo.
3. Un riesgo derivado: si la cabecera de la que se extrae la IP real fuese
   falsificable, un atacante podría provocar el bloqueo de terceros. Detrás de
   un borde gestionado, la IP debe salir de una cabecera que escriba el propio
   borde y que el cliente no pueda encadenar (por ejemplo
   `X-Envoy-External-Address`), pero **es un requisito de seguridad nuevo**
   que hay que enunciar antes de construir la función.

Recomendación: preséntese como **RF-11** explícito en la v1.2, con su
delimitación propia, y no como una consecuencia natural de RF-05. Colarlo sin
declararlo es lo que sí se leería como un cambio de alcance no acordado.

### 4.2 Qué gana la delimitación

Dos cosas que hoy no están escritas y que el hallazgo permite escribir con
precisión:

- **El sobre de inspección.** Qué se mira y qué no: los cuerpos por encima de
  `client_body_buffer_size` llegan marcados como truncados y **no se releen del
  disco**; hay cabeceras excluidas del escaneo por decisión explícita
  (`skipHeader`, `patterns.go:169`); no se inspeccionan respuestas; el TLS se
  termina aguas arriba en el despliegue actual.
- **El modelo de adversario.** Hasta dónde se pretende contener. Con estos datos
  puede enunciarse sin vaguedad: *un atacante que conoce las clases de ataque y
  aplica técnicas de ofuscación conocidas, pero no dispone de las firmas
  concretas ni de acceso a la máquina.* Un modelo de adversario explícito es lo
  que separa una evaluación de una demostración.

### 4.3 Qué le pasa al valor del proyecto

No cambia de dirección: cambia de estatus. Hoy la afirmación central —*el
sistema contiene tráfico malicioso externo*— se apoya en un suite que prueba
cobertura de firmas con entrada canónica. Después se apoya en una **tasa de
detección medida frente a evasión**, con cifra antes y después.

Y el hallazgo mismo es un resultado. Encontrar por método sistemático que 7 de
14 variantes de los propios ataques atraviesan el propio filtro, documentarlo y
cerrarlo con una medición comparativa es validación en sentido estricto. Una
batería de pruebas que sólo reporta éxitos no ha medido nada.

---

## 5. Qué debe resolver el documento técnico v1.2

> **Estado a 2026-09-24.** Los puntos 1 a 5 y el 7 están redactados en el
> borrador v1.2 de `technical-document.md` y su traducción
> `technical-document.es.md`, pendientes de aprobación. El punto 6 está incorporado como criterio no funcional
> ("Resistencia a evasión"), pero el corpus de variantes en sí **no está
> construido**: sigue siendo trabajo de implementación.


1. **RF-03** — cerrar la lista de "payloads conocidos". Enunciada en abierto, el
   alcance es infinito. Propuesta: SQLi, XSS, path traversal/LFI e inyección de
   comandos, y nada más en v1.2.
2. **RF-03** — añadir la normalización como requisito explícito, no como detalle
   de implementación. Es la pieza de la que depende que el resto del requisito
   signifique algo.
3. **RF-05** — decidir y escribir la granularidad. Si se limita por `(IP, ruta)`,
   un atacante obtiene un presupuesto por cada ruta: el presupuesto global por
   IP debe seguir existiendo **por encima** del específico, no sustituirlo.
4. **RF-11 (nuevo)** — bloqueo automático progresivo, con su delimitación y los
   riesgos de §4.1.
5. **§ Delimitación** — incorporar el sobre de inspección y el modelo de
   adversario de §4.2.
6. **§ Validación** — incorporar el corpus de evasión como nivel de prueba, con
   la tabla comparativa antes/después.
7. **RF-04** — dejar constancia de que la terminación TLS la resuelve el borde
   del proveedor en el despliegue actual, en lugar de figurar como diferido sin
   más.

Pendiente de decisión aparte, fuera de este hallazgo: RF-06 no contempla
**anclaje externo** del hash de cabeza, por lo que el truncado de la cola de la
cadena no es detectable. No afecta al filtrado y no se propone para v1.2, pero
debe figurar como limitación conocida.

---

## Anexo — sonda de evasión

Reproducible colocando este fichero en `engine/internal/rules/` y ejecutando
`go test ./engine/internal/rules/ -run Evasion -v`. No forma parte del árbol: es
instrumento de medida, y su versión definitiva debe integrarse en
`test/corpus/attacks.json` como casos permanentes.

```go
package rules

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/open-shield/open-shield/internal/model"
)

// '@' sustituye a la barra invertida para que el fuente no lleve escapes.
func unesc(s string) string { return strings.ReplaceAll(s, "@", string([]byte{92})) }

func TestEvasionProbe(t *testing.T) {
	set, _ := LoadSignatures("")
	sqli := NewPatternRule("sqli", set.SQLi, 8192)
	xss := NewPatternRule("xss", set.XSS, 8192)

	type c struct{ grupo, name, query, body string }
	cases := []c{
		{"A", "base: SQLi ' -- en form-urlencoded", "", "usuario=admin%27--&clave=x"},
		{"A", "  var: mismo ataque en JSON escapado", "", unesc(`{"usuario":"admin@u0027--"}`)},
		{"A", "  var: mismo ataque, JSON literal", "", `{"usuario":"admin'--"}`},

		{"B", "base: SQLi tautologia en query", "id=1%27%20OR%201%3D1--", ""},
		{"B", "  var: doble codificacion", "id=1%2527%2520OR%25201%253D1--", ""},
		{"B", "  var: JSON escapado", "", unesc(`{"id":"1@u0027 OR 1=1--"}`)},

		{"C", "base: XSS <script> en query", "q=%3Cscript%3Ealert(1)%3C/script%3E", ""},
		{"C", "  var: doble codificacion", "q=%253Cscript%253Ealert(1)%253C/script%253E", ""},
		{"C", "  var: entidades HTML", "q=&lt;script&gt;alert(1)&lt;/script&gt;", ""},
		{"C", "  var: JSON escapado", "", unesc(`{"c":"@u003cscript@u003ealert(1)@u003c/script@u003e"}`)},

		{"D", "clase ausente: path traversal", "file=../../../../etc/passwd", ""},
		{"D", "clase ausente: traversal codificado", "file=..%2f..%2f..%2fetc%2fpasswd", ""},
		{"D", "clase ausente: inyeccion de comandos", "host=127.0.0.1;cat%20/etc/passwd", ""},
		{"D", "clase ausente: LFI por wrapper php", "p=php://filter/convert.base64-encode/resource=index", ""},
	}

	prev := ""
	for _, tc := range cases {
		if tc.grupo != prev {
			fmt.Println()
			prev = tc.grupo
		}
		req := &model.RequestContext{Path: "/buscar", Query: tc.query, Body: tc.body, Headers: map[string]string{}}
		verdict, reason := "PASA  <-- EVADE", ""
		if v, r := sqli.Evaluate(context.Background(), req); v == model.Block {
			verdict, reason = "BLOQUEA", r
		} else if v, r := xss.Evaluate(context.Background(), req); v == model.Block {
			verdict, reason = "BLOQUEA", r
		}
		if i := strings.Index(reason, " matched"); i > 0 {
			reason = reason[:i]
		}
		fmt.Printf("  %-40s %-18s %s\n", tc.name, verdict, reason)
	}
	fmt.Println()
}
```
