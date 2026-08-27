//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/open-shield/open-shield/internal/events"
	"github.com/open-shield/open-shield/internal/model"
	"github.com/open-shield/open-shield/test/harness"
)

// events_test.go in internal/events runs against miniredis. What only a real
// server can show is what Pub/Sub does when nobody is listening, and how long a
// control notification actually takes to arrive.

func TestEventsSurviveARealRoundTrip(t *testing.T) {
	client := harness.Redis(t)
	ctx, cancel := context.WithCancel(harness.Context(t))
	defer cancel()

	const channel = "openshield:integration"
	stream := events.Subscribe(ctx, client, channel, 32, harness.QuietLog())
	harness.WaitForSubscriber(t, client, channel, 1)

	want := model.AuditEntry{
		ID:        "0f8fad5b-d9cb-469f-a165-70867728950e",
		RequestID: "req-1",
		Timestamp: time.Date(2026, 8, 25, 12, 0, 0, 123456000, time.UTC),
		Kind:      model.KindTraffic,
		Payload: map[string]any{
			"ip":      "203.0.113.7",
			"verdict": string(model.Block),
			"reason":  `sqli signature "union_select" matched in query: …x' UNION SELECT…`,
		},
		PrevHash: model.GenesisHash,
		Hash:     "abc123",
	}

	if err := events.NewPublisher(client, channel).Publish(ctx, want); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case got := <-stream:
		if got.ID != want.ID || got.Hash != want.Hash {
			t.Fatalf("identity changed in transit: %+v", got)
		}
		if !got.Timestamp.Equal(want.Timestamp) {
			t.Errorf("timestamp = %s, want %s", got.Timestamp, want.Timestamp)
		}
		if got.Payload["reason"] != want.Payload["reason"] {
			t.Errorf("reason = %v", got.Payload["reason"])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the entry never arrived")
	}
}

// Pub/Sub retains nothing. Publishing with nobody subscribed must be a
// successful no-op, not an error — the engine keeps deciding and recording
// whether or not a dashboard is open, and the durable record is the audit log.
func TestPublishingWithNoSubscriberIsNotAnError(t *testing.T) {
	client := harness.Redis(t)
	ctx := harness.Context(t)

	publisher := events.NewPublisher(client, "openshield:nobody-listening")
	for i := 0; i < 10; i++ {
		if err := publisher.Publish(ctx, model.AuditEntry{
			ID:      fmt.Sprintf("entry-%d", i),
			Kind:    model.KindTraffic,
			Payload: map[string]any{"i": i},
		}); err != nil {
			t.Fatalf("Publish %d: %v", i, err)
		}
	}
}

// A rule toggled in the dashboard reaches the engine over the control channel
// in under a second. The 30-second re-read is the fallback, not the mechanism.
func TestControlNotificationsReachASubscriber(t *testing.T) {
	client := harness.Redis(t)
	ctx, cancel := context.WithCancel(harness.Context(t))
	defer cancel()

	const channel = "openshield:integration"
	control := events.SubscribeControl(ctx, client, channel)
	harness.WaitForSubscriber(t, client, channel+events.ControlChannelSuffix, 1)

	publisher := events.NewPublisher(client, channel)

	start := time.Now()
	if err := publisher.Notify(ctx, "rules"); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	select {
	case kind := <-control:
		if kind != "rules" {
			t.Fatalf("received %q, want rules", kind)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("the notification took %v; the fallback re-read is 30s, this path is meant to be immediate", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the notification never arrived")
	}
}
