## Qué cambia y por qué

<!--
Qué hace este cambio y qué problema resuelve. Si toca una decisión de diseño,
enlaza la sección del documento técnico o la entrada de
docs/decisiones-implementacion.md que la explica.
-->

## Cómo se ha comprobado

<!--
Los checks de CI son obligatorios y se ejecutan solos. Esto es para lo que no
sale de ahí: qué probaste a mano, contra qué stack, y qué observaste.
-->

## Lista de comprobación

- [ ] `make test` y `make test-race` pasan en local.
- [ ] Hay tests nuevos para el comportamiento nuevo, o se explica abajo por qué no.
- [ ] Si toca las reglas de detección: hay un vector nuevo en `test/corpus/attacks.json`,
      y tráfico legítimo parecido en `benign.json`.
- [ ] Si toca el encadenado de hashes (`internal/model`, `internal/audit`):
      los tests de determinismo y los objetivos de fuzzing siguen pasando, y
      la desviación queda anotada en `docs/decisiones-implementacion.md`.
- [ ] Si añade una variable de entorno: está en `deploy/.env.example` con un
      comentario que dice qué hace y cómo elegir su valor (§5.5).
- [ ] Si cambia la latencia del camino de la petición: `make test-load` sigue
      dentro del presupuesto de 50 ms del §8.2.
- [ ] Los documentos que van en pareja se actualizaron los dos o ninguno:
      `documento-tecnico.md` ↔ `technical-document.md`, `README.md` ↔ `README.es.md`.

## Notas para quien revise

<!--
Lo que no se ve en el diff: alternativas descartadas, deuda que se asume a
propósito, o la parte que más conviene mirar con calma.
-->
