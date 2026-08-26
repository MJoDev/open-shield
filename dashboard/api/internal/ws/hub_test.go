package ws

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/open-shield/open-shield/internal/model"
)

// The hub is the last link of engine → Redis → hub → browser. Its two
// properties worth protecting are that one slow browser cannot stall the others,
// and that a disconnected browser is actually forgotten — a hub that leaks
// clients grows a slot per reload until the process is restarted.

func quietHub() *Hub {
	return NewHub(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func entry(id string) model.AuditEntry {
	return model.AuditEntry{
		ID:        id,
		RequestID: "req-" + id,
		Timestamp: time.Now().UTC(),
		Kind:      model.KindTraffic,
		Payload:   map[string]any{"ip": "203.0.113.7", "verdict": string(model.Block), "rule": "sqli"},
	}
}

// --- Fan-out ----------------------------------------------------------------

func TestBroadcastReachesEveryClient(t *testing.T) {
	h := quietHub()

	clients := make([]*client, 3)
	for i := range clients {
		clients[i] = &client{
			events: make(chan model.AuditEntry, clientBuffer),
			done:   make(chan struct{}),
		}
		h.add(clients[i])
	}

	h.broadcast(entry("a"))

	for i, c := range clients {
		select {
		case got := <-c.events:
			if got.ID != "a" {
				t.Errorf("client %d received %q, want %q", i, got.ID, "a")
			}
		default:
			t.Errorf("client %d received nothing", i)
		}
	}
}

// A browser left open on a laptop that went to sleep must not stall the live
// view of every other operator. The durable record is the audit log either way,
// so skipping a slow client costs nothing that matters.
func TestBroadcastSkipsAClientThatCannotKeepUp(t *testing.T) {
	h := quietHub()

	slow := &client{events: make(chan model.AuditEntry, 1), done: make(chan struct{})}
	fast := &client{events: make(chan model.AuditEntry, clientBuffer), done: make(chan struct{})}
	h.add(slow)
	h.add(fast)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			h.broadcast(entry("e"))
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("broadcast blocked on a client whose buffer was full")
	}

	if len(fast.events) != 50 {
		t.Errorf("the fast client received %d of 50 events", len(fast.events))
	}
	if len(slow.events) != 1 {
		t.Errorf("the slow client holds %d events, want its buffer of 1", len(slow.events))
	}
}

func TestClientsCountsConnections(t *testing.T) {
	h := quietHub()

	if h.Clients() != 0 {
		t.Fatalf("a new hub reports %d clients", h.Clients())
	}

	c := &client{events: make(chan model.AuditEntry, 1), done: make(chan struct{})}
	h.add(c)
	if h.Clients() != 1 {
		t.Fatalf("Clients() = %d after one connection, want 1", h.Clients())
	}

	h.remove(c)
	if h.Clients() != 0 {
		t.Fatalf("Clients() = %d after the connection closed, want 0", h.Clients())
	}

	// Removing twice must not panic on the already-closed done channel: the
	// handler removes on exit and the reader goroutine removes on read error,
	// and both happen when a browser disconnects.
	h.remove(c)
}

// --- The event loop ---------------------------------------------------------

func TestRunForwardsTheStreamUntilTheContextEnds(t *testing.T) {
	h := quietHub()
	c := &client{events: make(chan model.AuditEntry, clientBuffer), done: make(chan struct{})}
	h.add(c)

	stream := make(chan model.AuditEntry)
	ctx, cancel := context.WithCancel(context.Background())

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		h.Run(ctx, stream)
	}()

	stream <- entry("first")
	select {
	case got := <-c.events:
		if got.ID != "first" {
			t.Errorf("received %q, want first", got.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the event never reached the client")
	}

	cancel()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return when its context was cancelled")
	}

	// Shutting down closes every client, which is what makes the handlers
	// return instead of hanging on a hub that has stopped.
	if h.Clients() != 0 {
		t.Fatalf("Clients() = %d after shutdown, want 0", h.Clients())
	}
	select {
	case <-c.done:
	default:
		t.Fatal("the client was not told the hub had shut down")
	}
}

// Redis Pub/Sub delivers through a channel that the subscriber closes when it
// gives up. Run must treat that as a shutdown rather than spinning on a closed
// channel forever.
func TestRunStopsWhenTheStreamCloses(t *testing.T) {
	h := quietHub()
	stream := make(chan model.AuditEntry)

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		h.Run(context.Background(), stream)
	}()

	close(stream)
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return when the event stream closed")
	}
}

// --- Over a real connection -------------------------------------------------

func TestHandlerStreamsEventsToABrowser(t *testing.T) {
	h := quietHub()
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, handshake, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// On a successful upgrade the handshake response has no body to release —
	// the connection has been taken over. The nil check is not defensive
	// padding: dereferencing it panics.
	if handshake != nil && handshake.Body != nil {
		_ = handshake.Body.Close()
	}
	defer func() { _ = conn.CloseNow() }()

	waitForClients(t, h, 1)
	h.broadcast(entry("live"))

	_, raw, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var got model.AuditEntry
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode: %v — frame was %s", err, raw)
	}
	if got.ID != "live" {
		t.Fatalf("received %q, want live", got.ID)
	}
	if got.Payload["rule"] != "sqli" {
		t.Errorf("payload lost the rule: %v", got.Payload)
	}
}

// A hub that keeps a slot per closed connection grows one entry per dashboard
// reload, and ws_clients on the status view stops meaning anything.
func TestHandlerForgetsADisconnectedBrowser(t *testing.T) {
	h := quietHub()
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, handshake, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if handshake != nil && handshake.Body != nil {
		_ = handshake.Body.Close()
	}
	waitForClients(t, h, 1)

	if err := conn.Close(websocket.StatusNormalClosure, "done"); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitForClients(t, h, 0)
}

// The live feed carries source addresses, request paths and block reasons —
// precisely what an attacker would use to tune a payload past the filters. The
// upgrade is same-origin only, so a page on another site cannot open one.
func TestHandlerRefusesACrossOriginUpgrade(t *testing.T) {
	h := quietHub()
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Origin", "http://evil.test")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("a cross-origin page was allowed to open the live feed")
	}
	if h.Clients() != 0 {
		t.Fatalf("Clients() = %d after a refused upgrade", h.Clients())
	}
}

// waitForClients polls until the hub reports want connections. The handler
// registers and deregisters from its own goroutine, so there is no point at
// which a test can read the count synchronously.
func waitForClients(t *testing.T, h *Hub, want int) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.Clients() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("hub reports %d clients, want %d", h.Clients(), want)
}
