// Package events carries audit entries from the rules engine to whoever is
// watching, over Redis Pub/Sub.
//
// This is the Observer relationship of §5.4: the engine publishes every
// decision to a channel and does not know who is subscribed. The dashboard can
// restart, fall behind or never connect at all, and the engine keeps deciding
// and recording. The trade-off is that Pub/Sub does not retain anything — a
// subscriber that is not connected misses the event. That is acceptable here
// because the durable record is the audit log; this channel only feeds the live
// view.
package events

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/open-shield/open-shield/internal/model"
)

// ControlChannelSuffix names the side channel used to tell the engine that its
// cached rule configuration is stale. It is derived from the events channel so
// a single OS_EVENTS_CHANNEL setting configures both.
const ControlChannelSuffix = ":control"

// Publisher writes audit entries to the events channel. It satisfies
// audit.Publisher.
type Publisher struct {
	client  *redis.Client
	channel string
}

// NewPublisher returns a Publisher writing to the given channel.
func NewPublisher(client *redis.Client, channel string) *Publisher {
	return &Publisher{client: client, channel: channel}
}

// Publish sends one entry. A failure here is not fatal to the caller: the entry
// is already durable in the audit log by the time it is published.
func (p *Publisher) Publish(ctx context.Context, entry model.AuditEntry) error {
	payload, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("events: marshal entry: %w", err)
	}
	if err := p.client.Publish(ctx, p.channel, payload).Err(); err != nil {
		return fmt.Errorf("events: publish: %w", err)
	}
	return nil
}

// Notify sends a control message on the control channel, e.g. to tell the
// engine that the IP blocklist changed.
func (p *Publisher) Notify(ctx context.Context, kind string) error {
	ch := p.channel + ControlChannelSuffix
	if err := p.client.Publish(ctx, ch, kind).Err(); err != nil {
		return fmt.Errorf("events: notify %s: %w", kind, err)
	}
	return nil
}

// Subscribe streams audit entries from the events channel until ctx is done.
//
// go-redis reconnects underneath, so a Redis restart shows up as a gap in the
// live feed rather than as a dead subscription. Entries that arrive while the
// consumer is slow are dropped instead of blocking the reader: the live view is
// a view, and the record of truth is the audit log.
func Subscribe(ctx context.Context, client *redis.Client, channel string, buffer int, log *slog.Logger) <-chan model.AuditEntry {
	if buffer <= 0 {
		buffer = 256
	}
	if log == nil {
		log = slog.Default()
	}

	out := make(chan model.AuditEntry, buffer)

	go func() {
		defer close(out)

		sub := client.Subscribe(ctx, channel)
		defer func() { _ = sub.Close() }()

		messages := sub.Channel(redis.WithChannelSize(buffer))
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-messages:
				if !ok {
					return
				}
				var entry model.AuditEntry
				if err := json.Unmarshal([]byte(msg.Payload), &entry); err != nil {
					log.Warn("events: dropping malformed message", "error", err)
					continue
				}
				select {
				case out <- entry:
				default:
					log.Warn("events: subscriber is behind, dropping live event", "id", entry.ID)
				}
			}
		}
	}()

	return out
}

// SubscribeControl streams control notifications from the control channel.
func SubscribeControl(ctx context.Context, client *redis.Client, channel string) <-chan string {
	out := make(chan string, 8)

	go func() {
		defer close(out)

		sub := client.Subscribe(ctx, channel+ControlChannelSuffix)
		defer func() { _ = sub.Close() }()

		messages := sub.Channel()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-messages:
				if !ok {
					return
				}
				select {
				case out <- msg.Payload:
				default:
				}
			}
		}
	}()

	return out
}

// NewClient opens a Redis connection and verifies it is reachable, so a bad
// address fails at startup instead of on the first request.
func NewClient(ctx context.Context, addr, password string, db int) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           db,
		DialTimeout:  3 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("events: connect to redis at %s: %w", addr, err)
	}
	return client, nil
}
