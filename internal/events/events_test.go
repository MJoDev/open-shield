package events

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/open-shield/open-shield/internal/model"
)

// This is the Observer relationship of §5.4: the engine publishes and does not
// know who is listening. Two properties matter and neither is visible from
// either side alone — that an entry survives the trip intact, and that a
// subscriber which has fallen behind is dropped rather than allowed to back the
// publisher up.
//
// miniredis speaks the real protocol, so this covers the encoding and the
// channel semantics. The behaviour under a real server restart belongs to
// test/integration.

const testChannel = "openshield:test"

func newRedis(t *testing.T) *redis.Client {
	t.Helper()

	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func sampleEntry() model.AuditEntry {
	return model.AuditEntry{
		ID:        "0f8fad5b-d9cb-469f-a165-70867728950e",
		RequestID: "req-1",
		Timestamp: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
		Kind:      model.KindTraffic,
		Payload: map[string]any{
			"ip":      "203.0.113.7",
			"verdict": string(model.Block),
			"rule":    "sqli",
			"reason":  `sqli signature "union_select" matched in query: …x' UNION SELECT…`,
		},
		PrevHash: model.GenesisHash,
		Hash:     "abc123",
	}
}

// waitForSubscriber gives the subscriber goroutine time to register with Redis.
// Publishing before it has subscribed delivers to nobody: Pub/Sub retains
// nothing, which is the trade-off documented on the package.
func waitForSubscriber(t *testing.T, client *redis.Client, channel string, want int64) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		counts, err := client.PubSubNumSub(context.Background(), channel).Result()
		if err == nil && counts[channel] >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no subscriber appeared on %s", channel)
}

// --- Round trip -------------------------------------------------------------

func TestPublishedEntriesArriveIntact(t *testing.T) {
	client := newRedis(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := Subscribe(ctx, client, testChannel, 16, quietLog())
	waitForSubscriber(t, client, testChannel, 1)

	want := sampleEntry()
	if err := NewPublisher(client, testChannel).Publish(ctx, want); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case got := <-stream:
		// Everything the live view renders has to survive the trip, including
		// the block reason — it is the only part of the payload that says why.
		if got.ID != want.ID || got.RequestID != want.RequestID || got.Hash != want.Hash {
			t.Fatalf("identity fields changed:\n  got  %+v\n  want %+v", got, want)
		}
		if !got.Timestamp.Equal(want.Timestamp) {
			t.Errorf("timestamp = %s, want %s", got.Timestamp, want.Timestamp)
		}
		if got.Payload["reason"] != want.Payload["reason"] {
			t.Errorf("reason = %v, want %v", got.Payload["reason"], want.Payload["reason"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the entry never arrived")
	}
}

func TestSubscribeStopsWhenItsContextEnds(t *testing.T) {
	client := newRedis(t)
	ctx, cancel := context.WithCancel(context.Background())

	stream := Subscribe(ctx, client, testChannel, 4, quietLog())
	waitForSubscriber(t, client, testChannel, 1)

	cancel()

	// The channel is closed on the way out, which is what tells ws.Hub.Run to
	// shut down rather than block on a stream nobody will ever write to again.
	select {
	case _, open := <-stream:
		if open {
			// Drain one buffered entry and try again.
			select {
			case _, open := <-stream:
				if open {
					t.Fatal("the stream stayed open after the context was cancelled")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the stream was never closed")
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stream was never closed")
	}
}

// A malformed message must not kill the subscription. Anything with access to
// the channel could publish nonsense, and losing the live feed to it would be a
// denial of service against the operator's own view.
func TestSubscribeSkipsMalformedMessages(t *testing.T) {
	client := newRedis(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := Subscribe(ctx, client, testChannel, 16, quietLog())
	waitForSubscriber(t, client, testChannel, 1)

	if err := client.Publish(ctx, testChannel, "no es json").Err(); err != nil {
		t.Fatalf("publish junk: %v", err)
	}
	if err := NewPublisher(client, testChannel).Publish(ctx, sampleEntry()); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case got := <-stream:
		if got.ID != sampleEntry().ID {
			t.Fatalf("received %q, want the well-formed entry", got.ID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the subscription died on a malformed message")
	}
}

// The live view is a view; the record of truth is the audit log. A consumer
// that has stopped reading is dropped rather than allowed to back up the
// subscriber goroutine.
func TestSubscribeDropsEventsForAConsumerThatStopsReading(t *testing.T) {
	client := newRedis(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := Subscribe(ctx, client, testChannel, 1, quietLog())
	waitForSubscriber(t, client, testChannel, 1)

	publisher := NewPublisher(client, testChannel)
	entry := sampleEntry()

	// Publishing far more than the buffer holds, without ever reading.
	for i := 0; i < 200; i++ {
		if err := publisher.Publish(ctx, entry); err != nil {
			t.Fatalf("Publish %d: %v", i, err)
		}
	}

	// The one thing that must not happen is a stall: whatever the count, the
	// consumer can still read and the publisher was never blocked.
	select {
	case <-stream:
	case <-time.After(5 * time.Second):
		t.Fatal("nothing readable after 200 events; the subscriber stalled")
	}
}

// --- The control channel ----------------------------------------------------

// Rule changes reach the engine over a side channel derived from the same
// setting, so one OS_EVENTS_CHANNEL configures both. If the two names ever
// disagree, a rule toggled in the dashboard silently waits for the engine's
// 30-second re-read instead of taking effect at once.
func TestNotifyReachesTheControlChannel(t *testing.T) {
	client := newRedis(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	control := SubscribeControl(ctx, client, testChannel)
	waitForSubscriber(t, client, testChannel+ControlChannelSuffix, 1)

	if err := NewPublisher(client, testChannel).Notify(ctx, "ipblock"); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	select {
	case kind := <-control:
		if kind != "ipblock" {
			t.Fatalf("received %q, want ipblock", kind)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the notification never arrived")
	}
}

// The control channel must not carry decision events, or every blocked request
// would make the engine reload its configuration.
func TestTheTwoChannelsAreSeparate(t *testing.T) {
	client := newRedis(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	control := SubscribeControl(ctx, client, testChannel)
	events := Subscribe(ctx, client, testChannel, 16, quietLog())
	waitForSubscriber(t, client, testChannel, 1)
	waitForSubscriber(t, client, testChannel+ControlChannelSuffix, 1)

	publisher := NewPublisher(client, testChannel)
	if err := publisher.Publish(ctx, sampleEntry()); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case <-events:
	case <-time.After(5 * time.Second):
		t.Fatal("the entry never reached the events channel")
	}

	select {
	case kind := <-control:
		t.Fatalf("a decision reached the control channel as %q", kind)
	case <-time.After(200 * time.Millisecond):
	}
}

// --- Connecting -------------------------------------------------------------

// A bad address must fail at startup, not on the first request that needs
// Redis — §5.5 again, and the difference between a container that refuses to
// come up and one that comes up broken.
func TestNewClientRefusesAnUnreachableServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := NewClient(ctx, "127.0.0.1:1", "", 0)
	if err == nil {
		_ = client.Close()
		t.Fatal("NewClient succeeded against a port nothing is listening on")
	}
}

func TestNewClientVerifiesTheConnection(t *testing.T) {
	server := miniredis.RunT(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := NewClient(ctx, server.Addr(), "", 0)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("the returned client does not work: %v", err)
	}
}
