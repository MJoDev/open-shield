package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/open-shield/open-shield/internal/model"
)

// AuditClient records administrative actions through the engine.
//
// The dashboard deliberately has no write access to the chain of its own. Each
// entry's hash covers the previous entry, so appends must come from a single
// writer; the engine owns it, and this is how the dashboard asks for a link to
// be added.
type AuditClient struct {
	baseURL string
	client  *http.Client
}

// NewAuditClient returns a client for the engine at baseURL.
func NewAuditClient(baseURL string) *AuditClient {
	return &AuditClient{
		baseURL: baseURL,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// RecordAdmin appends an administrative entry and waits for it to be durable.
//
// Callers must treat an error here as a reason to abandon the change they were
// about to make. §6.1 requires configuration changes to be on the record, and a
// change to what the proxy blocks that nobody can later account for is worse
// than a change that did not happen.
func (c *AuditClient) RecordAdmin(ctx context.Context, actor, action string, details map[string]any) error {
	payload := map[string]any{
		"actor":  actor,
		"action": action,
	}
	for k, v := range details {
		// actor and action are set by the server, never by the caller's detail
		// map, so an operator cannot attribute their own change to someone else.
		if k == "actor" || k == "action" {
			continue
		}
		payload[k] = v
	}

	body, err := json.Marshal(map[string]any{
		"kind":    model.KindAdmin,
		"payload": payload,
	})
	if err != nil {
		return fmt.Errorf("audit client: encode entry: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/audit", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("audit client: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("audit client: reach the engine: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusCreated {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("audit client: engine answered %d: %s", resp.StatusCode, bytes.TrimSpace(detail))
	}
	return nil
}

// EngineStatus fetches the engine's self-report for the dashboard's health
// view.
func (c *AuditClient) EngineStatus(ctx context.Context) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/status", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("audit client: reach the engine: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var status map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&status); err != nil {
		return nil, fmt.Errorf("audit client: decode engine status: %w", err)
	}
	return status, nil
}
