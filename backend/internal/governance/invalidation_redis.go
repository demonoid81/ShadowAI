//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).

package governance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	"github.com/redis/go-redis/v9"
)

const governanceInvalidationChannel = "shadowai:governance:policy:invalidate:v1"

// RedisInvalidationBus publishes governance policy invalidations to all
// replicas. It intentionally carries only org/policy identifiers, never policy
// payloads.
type RedisInvalidationBus struct {
	client     redis.UniversalClient
	channel    string
	instanceID string
}

type governanceInvalidationMessage struct {
	OrgID       string `json:"org_id"`
	PolicyID    string `json:"policy_id,omitempty"`
	PublisherID string `json:"publisher_id"`
}

// NewRedisInvalidationBus creates a Redis-backed invalidation bus.
func NewRedisInvalidationBus(client redis.UniversalClient) *RedisInvalidationBus {
	return &RedisInvalidationBus{
		client:     client,
		channel:    governanceInvalidationChannel,
		instanceID: randomInvalidationInstanceID(),
	}
}

// PublishGovernanceInvalidation notifies other replicas that orgID policy was
// updated and their in-process snapshots should be dropped.
func (b *RedisInvalidationBus) PublishGovernanceInvalidation(ctx context.Context, orgID, policyID string) error {
	if b == nil || b.client == nil {
		return nil
	}
	if orgID == "" {
		return nil
	}
	msg := governanceInvalidationMessage{
		OrgID:       orgID,
		PolicyID:    policyID,
		PublisherID: b.instanceID,
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal invalidation: %w", err)
	}
	return b.client.Publish(ctx, b.channel, payload).Err()
}

// Run subscribes to governance invalidation events until ctx is cancelled.
func (b *RedisInvalidationBus) Run(ctx context.Context, cache *CachingRepository) {
	if b == nil || b.client == nil || cache == nil {
		return
	}
	pubsub := b.client.Subscribe(ctx, b.channel)
	defer pubsub.Close() //nolint:errcheck
	if _, err := pubsub.Receive(ctx); err != nil {
		log.Printf("governance cache: invalidation subscribe failed: %v", err)
		return
	}
	log.Printf("governance cache: distributed invalidation subscriber started (channel=%s)", b.channel)
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-pubsub.Channel():
			if !ok {
				return
			}
			if err := b.applyMessage(cache, msg.Payload); err != nil {
				log.Printf("governance cache: invalidation message ignored: %v", err)
			}
		}
	}
}

func (b *RedisInvalidationBus) applyMessage(cache *CachingRepository, payload string) error {
	var msg governanceInvalidationMessage
	if err := json.Unmarshal([]byte(payload), &msg); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if msg.OrgID == "" {
		return fmt.Errorf("empty org_id")
	}
	if msg.PublisherID != "" && msg.PublisherID == b.instanceID {
		return nil
	}
	cache.Invalidate(msg.OrgID)
	return nil
}

func randomInvalidationInstanceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}
