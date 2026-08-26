// Command demo-backend stands in for the application being protected.
//
// It exists so that `docker compose up` produces a working system with nothing
// else to install (RF-10), and so the smoke test has something real to reach.
// It renders whatever request arrives, including the correlation id the proxy
// attached — which makes it easy to see that a request that reached here is
// the same one recorded in the audit log.
package main

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	addr := os.Getenv("DEMO_ADDR")
	if addr == "" {
		addr = ":3000"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","component":"demo-backend"}`))
	})
	mux.HandleFunc("/api/echo", echoJSON)
	mux.HandleFunc("/", page)

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("demo backend listening on %s", addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func echoJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"method":     r.Method,
		"path":       r.URL.Path,
		"query":      r.URL.RawQuery,
		"request_id": r.Header.Get("X-Request-ID"),
		"client_ip":  r.Header.Get("X-Real-IP"),
	})
}

func page(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = "(none — this request did not come through the proxy)"
	}

	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names)

	var headers strings.Builder
	for _, name := range names {
		fmt.Fprintf(&headers, "<tr><th>%s</th><td>%s</td></tr>",
			html.EscapeString(name), html.EscapeString(r.Header.Get(name)))
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// A write that fails here means the client hung up mid-response; there is
	// nothing left to say to them, and nothing to log that is not noise.
	_, _ = fmt.Fprintf(w, demoPage,
		html.EscapeString(requestID),
		html.EscapeString(r.Method),
		html.EscapeString(r.URL.Path),
		html.EscapeString(r.URL.RawQuery),
		html.EscapeString(r.Header.Get("X-Real-IP")),
		headers.String())
}

const demoPage = `<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>Aplicación protegida — open-shield</title>
<style>
 body{font-family:system-ui,sans-serif;margin:3rem auto;max-width:48rem;
      padding:0 1.5rem;line-height:1.6;color:#1c1f24;background:#f7f8fa}
 .ok{background:#e6f4ea;border-left:4px solid #1e8e3e;padding:.75rem 1rem;
     border-radius:.25rem;margin:1.5rem 0}
 table{border-collapse:collapse;width:100%%;margin-top:1rem;background:#fff;
       border-radius:.4rem;overflow:hidden;font-size:.9rem}
 th,td{padding:.5rem .75rem;text-align:left;border-bottom:1px solid #e8eaee;
       vertical-align:top}
 th{width:14rem;font-weight:600;color:#4a5058}
 code{background:#e8eaee;padding:.15rem .35rem;border-radius:.25rem}
</style></head><body>

<h1>Aplicación protegida</h1>

<div class="ok">
  Esta petición atravesó el proxy y el motor de reglas la permitió.
</div>

<p>Identificador de correlación — el mismo que aparece en el log de auditoría:</p>
<p><code>%s</code></p>

<table>
 <tr><th>Método</th><td>%s</td></tr>
 <tr><th>Ruta</th><td>%s</td></tr>
 <tr><th>Query</th><td>%s</td></tr>
 <tr><th>IP de origen (X-Real-IP)</th><td>%s</td></tr>
 %s
</table>

<p style="margin-top:2rem;font-size:.9rem;color:#4a5058">
 Prueba a pedir <code>/?id=1' OR '1'='1</code> — el motor debería bloquearla
 antes de que llegue hasta aquí.
</p>
</body></html>
`
