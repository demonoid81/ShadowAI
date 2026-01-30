package proxy

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// fakeRedis implements RedisClient with in-memory storage for testing.
type fakeRedis struct {
	mu   sync.Mutex
	data map[string]string
	lists map[string][]string
}

func newFakeRedis() *fakeRedis {
	return &fakeRedis{
		data:  make(map[string]string),
		lists: make(map[string][]string),
	}
}

func (f *fakeRedis) Incr(_ context.Context, key string) *redis.IntCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, _ := strconv.ParseInt(f.data[key], 10, 64)
	v++
	f.data[key] = strconv.FormatInt(v, 10)
	cmd := redis.NewIntCmd(context.Background())
	cmd.SetVal(v)
	return cmd
}

func (f *fakeRedis) Expire(_ context.Context, _ string, _ time.Duration) *redis.BoolCmd {
	cmd := redis.NewBoolCmd(context.Background())
	cmd.SetVal(true)
	return cmd
}

func (f *fakeRedis) Get(_ context.Context, key string) *redis.StringCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := redis.NewStringCmd(context.Background())
	v, ok := f.data[key]
	if !ok {
		cmd.SetErr(redis.Nil)
		return cmd
	}
	cmd.SetVal(v)
	return cmd
}

func (f *fakeRedis) LPush(_ context.Context, key string, values ...interface{}) *redis.IntCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range values {
		s := ""
		switch val := v.(type) {
		case int64:
			s = strconv.FormatInt(val, 10)
		case string:
			s = val
		}
		f.lists[key] = append([]string{s}, f.lists[key]...)
	}
	cmd := redis.NewIntCmd(context.Background())
	cmd.SetVal(int64(len(f.lists[key])))
	return cmd
}

func (f *fakeRedis) LTrim(_ context.Context, key string, start, stop int64) *redis.StatusCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := f.lists[key]
	if int(stop)+1 < len(list) {
		f.lists[key] = list[:stop+1]
	}
	cmd := redis.NewStatusCmd(context.Background())
	cmd.SetVal("OK")
	return cmd
}

func (f *fakeRedis) LRange(_ context.Context, key string, start, stop int64) *redis.StringSliceCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := redis.NewStringSliceCmd(context.Background())
	list := f.lists[key]
	if len(list) == 0 {
		cmd.SetVal(nil)
		return cmd
	}
	end := int(stop)
	if stop < 0 {
		end = len(list) - 1
	}
	if end >= len(list) {
		end = len(list) - 1
	}
	cmd.SetVal(list[start : end+1])
	return cmd
}

func TestHealthTracker_RecordSuccessAndGetHealth(t *testing.T) {
	fr := newFakeRedis()
	ht := NewHealthTracker(fr)
	ctx := context.Background()

	ht.RecordSuccess(ctx, "openai", 100)
	ht.RecordSuccess(ctx, "openai", 200)
	ht.RecordSuccess(ctx, "openai", 300)

	health := ht.GetHealth(ctx, "openai")

	if health.SuccessCount != 3 {
		t.Errorf("SuccessCount = %d, want 3", health.SuccessCount)
	}
	if health.FailCount != 0 {
		t.Errorf("FailCount = %d, want 0", health.FailCount)
	}
	if health.SuccessRate != 1.0 {
		t.Errorf("SuccessRate = %f, want 1.0", health.SuccessRate)
	}
	if health.AvgLatencyMs != 200.0 {
		t.Errorf("AvgLatencyMs = %f, want 200.0", health.AvgLatencyMs)
	}
}

func TestHealthTracker_RecordFailureAffectsRate(t *testing.T) {
	fr := newFakeRedis()
	ht := NewHealthTracker(fr)
	ctx := context.Background()

	ht.RecordSuccess(ctx, "anthropic", 100)
	ht.RecordFailure(ctx, "anthropic")

	health := ht.GetHealth(ctx, "anthropic")

	if health.SuccessCount != 1 {
		t.Errorf("SuccessCount = %d, want 1", health.SuccessCount)
	}
	if health.FailCount != 1 {
		t.Errorf("FailCount = %d, want 1", health.FailCount)
	}
	if health.SuccessRate != 0.5 {
		t.Errorf("SuccessRate = %f, want 0.5", health.SuccessRate)
	}
}

func TestHealthTracker_GetAllHealth(t *testing.T) {
	fr := newFakeRedis()
	ht := NewHealthTracker(fr)
	ctx := context.Background()

	ht.RecordSuccess(ctx, "openai", 50)
	ht.RecordSuccess(ctx, "anthropic", 150)

	allHealth := ht.GetAllHealth(ctx, []string{"openai", "anthropic"})

	if len(allHealth) != 2 {
		t.Fatalf("GetAllHealth returned %d providers, want 2", len(allHealth))
	}
	if allHealth["openai"].AvgLatencyMs != 50.0 {
		t.Errorf("openai AvgLatencyMs = %f, want 50.0", allHealth["openai"].AvgLatencyMs)
	}
	if allHealth["anthropic"].AvgLatencyMs != 150.0 {
		t.Errorf("anthropic AvgLatencyMs = %f, want 150.0", allHealth["anthropic"].AvgLatencyMs)
	}
}
