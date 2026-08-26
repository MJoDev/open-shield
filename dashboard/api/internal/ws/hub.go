// Package ws fans audit events out to the browsers watching the live view.
//
// The chain is: engine → Redis Pub/Sub → this hub → WebSocket. The hub is the
// only part that knows a browser exists; the engine publishes into Redis and is
// finished (§5.4).
package ws

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/open-shield/open-shield/internal/model"
)

// clientBuffer is how many events may queue for one browser before it is
// considered too slow to keep up.
const clientBuffer = 128

// Hub keeps the set of connected browsers.
type Hub struct {
	log *slog.Logger

	mu      sync.RWMutex
	clients map[*client]struct{}
}

type client struct {
	events chan model.AuditEntry
	done   chan struct{}
}

// NewHub returns an empty hub.
func NewHub(log *slog.Logger) *Hub {
	if log == nil {
		log = slog.Default()
	}
	return &Hub{log: log, clients: map[*client]struct{}{}}
}

// Run reads from the event stream and copies each event to every connected
// browser, until ctx is done.
func (h *Hub) Run(ctx context.Context, stream <-chan model.AuditEntry) {
	for {
		select {
		case <-ctx.Done():
			h.closeAll()
			return
		case entry, ok := <-stream:
			if !ok {
				h.closeAll()
				return
			}
			h.broadcast(entry)
		}
	}
}

// broadcast copies one event to every client.
//
// A client whose buffer is full is skipped, not waited for. One browser left
// open on a laptop that went to sleep must not stall the live view of every
// other operator — and the durable record is the audit log either way.
func (h *Hub) broadcast(entry model.AuditEntry) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for c := range h.clients {
		select {
		case c.events <- entry:
		default:
			// Skipped: this client is behind.
		}
	}
}

// Clients reports how many browsers are connected, for the status endpoint.
func (h *Hub) Clients() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (h *Hub) add(c *client) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
}

func (h *Hub) remove(c *client) {
	h.mu.Lock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.done)
	}
	h.mu.Unlock()
}

func (h *Hub) closeAll() {
	h.mu.Lock()
	for c := range h.clients {
		delete(h.clients, c)
		close(c.done)
	}
	h.mu.Unlock()
}

// Handler upgrades a request to a WebSocket and streams events to it.
//
// It must be mounted behind authentication: the live feed carries source
// addresses, paths and block reasons, which is exactly the information an
// attacker would want in order to tune a payload past the filters.
func (h *Hub) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// Same-origin only: the dashboard API serves the SPA itself, so a
			// cross-origin upgrade is never legitimate here.
			OriginPatterns: nil,
		})
		if err != nil {
			h.log.Warn("websocket upgrade failed", "error", err)
			return
		}

		c := &client{
			events: make(chan model.AuditEntry, clientBuffer),
			done:   make(chan struct{}),
		}
		h.add(c)
		defer h.remove(c)

		ctx := r.Context()
		defer func() { _ = conn.CloseNow() }()

		// A reader goroutine is required even though the protocol is one-way:
		// without it, a close frame from the browser is never noticed and the
		// connection leaks until the write timeout fires.
		go func() {
			for {
				if _, _, err := conn.Read(ctx); err != nil {
					h.remove(c)
					return
				}
			}
		}()

		ping := time.NewTicker(30 * time.Second)
		defer ping.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-c.done:
				return
			case entry := <-c.events:
				if err := writeEntry(ctx, conn, entry); err != nil {
					return
				}
			case <-ping.C:
				// Keeps intermediaries from dropping an idle connection during
				// quiet traffic, and detects a browser that vanished.
				pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				err := conn.Ping(pingCtx)
				cancel()
				if err != nil {
					return
				}
			}
		}
	}
}

func writeEntry(ctx context.Context, conn *websocket.Conn, entry model.AuditEntry) error {
	payload, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return conn.Write(writeCtx, websocket.MessageText, payload)
}
