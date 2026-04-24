//go:build enterprise && integration

// PR-W4.3.1: live immudb integration harness using immudb built-in REST.
//
// Поднимает один codenotary/immudb:latest контейнер через testcontainers-go.
// Использует профиль immudb_v2 (POST /api/v2/*, session-based auth).
// Тест не SKIP'ает при успешном запуске Docker — он должен ПРОХОДИТЬ.
//
// При недоступности Docker или образа — t.Skip (setup issue, не наш баг).
//
// Запуск:
//
//	cd backend && go test -tags 'enterprise integration' ./integration -run TestImmuDB -count=1 -v -timeout 5m
package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/shadowai/backend/internal/chain"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// startImmudb поднимает codenotary/immudb:latest контейнер.
// Ждёт "web-api server enabled" в логах — сигнал готовности REST API.
// При недоступности Docker/образа вызывает t.Skip.
func startImmudb(t *testing.T) (addr string, teardown func()) {
	t.Helper()
	ctx := context.Background()

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "codenotary/immudb:latest",
			ExposedPorts: []string{"8080/tcp"},
			WaitingFor: wait.ForAll(
				wait.ForListeningPort("8080/tcp"),
				wait.ForLog("web-api server enabled").
					WithStartupTimeout(90*time.Second),
			).WithDeadline(120 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Skipf("immudb container unavailable (Docker or image pull?): %v", err)
	}

	host, _ := c.Host(ctx)
	port, _ := c.MappedPort(ctx, "8080")
	restAddr := host + ":" + port.Port()

	teardown = func() {
		_ = c.Terminate(ctx)
	}
	return restAddr, teardown
}

// TestImmuDBIntegration_HappyPath — full live flow: DialImmuDB → Write → Verify.
func TestImmuDBIntegration_HappyPath(t *testing.T) {
	addr, teardown := startImmudb(t)
	defer teardown()

	ctx := context.Background()
	opts := chain.ImmuDBOptions{Profile: chain.ProfileImmudbV2}
	client, err := dialImmuDBWithRetry(ctx, addr, "immudb", "immudb", "defaultdb", opts, 6, 3*time.Second)
	if err != nil {
		t.Fatalf("DialImmuDB failed after retries: %v", err)
	}
	sink := chain.NewImmuDBSink(client, "defaultdb")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	hashes := [][]byte{
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
	}
	a := &chain.AnchorRecord{
		TableName:  "audit_logs",
		SeqLo:      1,
		SeqHi:      10,
		RowCount:   3,
		MerkleRoot: chain.ComputeMerkleRoot(hashes),
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
	}
	a.SinkName = sink.Name()
	a.SinkRef = sink.BuildRef(a)
	if err := chain.SignAnchor(a, priv, "integration-test-key"); err != nil {
		t.Fatalf("SignAnchor: %v", err)
	}
	manifest, _ := chain.MarshalSignedManifest(a)
	if err := sink.Write(ctx, manifest, a.SinkRef); err != nil {
		t.Fatalf("Write to real immudb: %v", err)
	}
	ok, err := chain.VerifyImmuDBSinkRecord(ctx, sink, a, pub)
	if err != nil {
		t.Fatalf("VerifyImmuDBSinkRecord: %v", err)
	}
	if !ok {
		t.Error("VerifyImmuDBSinkRecord returned false — field mismatch or signature failure")
	}
	t.Logf("W4.3.1 happy path PASSED: written and verified anchor via immudb built-in REST (addr=%s)", addr)
}

// TestImmuDBIntegration_WrongPubKey — wrong pubkey → verification returns false.
func TestImmuDBIntegration_WrongPubKey(t *testing.T) {
	addr, teardown := startImmudb(t)
	defer teardown()

	ctx := context.Background()
	opts := chain.ImmuDBOptions{Profile: chain.ProfileImmudbV2}
	client, err := dialImmuDBWithRetry(ctx, addr, "immudb", "immudb", "defaultdb", opts, 6, 3*time.Second)
	if err != nil {
		t.Fatalf("DialImmuDB failed after retries: %v", err)
	}
	sink := chain.NewImmuDBSink(client, "defaultdb")

	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	a := &chain.AnchorRecord{
		TableName:  "admin_event_logs",
		SeqLo:      11,
		SeqHi:      20,
		RowCount:   1,
		MerkleRoot: bytes.Repeat([]byte{0xFF}, 32),
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
	}
	a.SinkName = sink.Name()
	a.SinkRef = sink.BuildRef(a)
	_ = chain.SignAnchor(a, priv1, "integration-key-1")

	manifest, _ := chain.MarshalSignedManifest(a)
	if err := sink.Write(ctx, manifest, a.SinkRef); err != nil {
		t.Fatalf("Write: %v", err)
	}
	ok, err := chain.VerifyImmuDBSinkRecord(ctx, sink, a, pub2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("wrong pubkey: expected false, got true")
	}
	t.Logf("W4.3.1 negative test PASSED: wrong pubkey correctly rejected (addr=%s)", addr)
}

func dialImmuDBWithRetry(ctx context.Context, addr, user, pass, db string, opts chain.ImmuDBOptions, maxAttempts int, delay time.Duration) (*chain.HTTPImmuDBClient, error) {
	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		c, err := chain.DialImmuDBWithOptions(ctx, addr, user, pass, db, opts)
		if err == nil {
			return c, nil
		}
		lastErr = err
		if i < maxAttempts-1 {
			time.Sleep(delay)
		}
	}
	return nil, fmt.Errorf("after %d attempts: %w", maxAttempts, lastErr)
}
