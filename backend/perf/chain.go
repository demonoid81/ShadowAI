package perf

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"time"

	"github.com/shadowai/backend/internal/chain"
)

// ChainHMACVerify benchmarks chain.Verify() — the per-row HMAC-SHA256 computation
// that runs for every row during VerifyAuditLogs. No DB required.
func ChainHMACVerify(r *Runner) BenchResult {
	secret := []byte("bench-chain-secret-32-chars-paddd")
	prevHash := make([]byte, 32)
	canonical := "v2|aaaaaaaa-0000-4000-8000-000000000001|gpt-4o|openai|/v1/chat/completions|200|10|20|30|100|false|{}|allowed|stream_completed|||1714089601|org-bench"

	// Pre-compute the expected storedHash so chain.Verify() returns true.
	mac := hmac.New(sha256.New, secret)
	mac.Write(prevHash)
	mac.Write([]byte(canonical))
	storedHash := mac.Sum(nil)

	return r.Run("ChainHMACVerify",
		"chain.Verify() HMAC-SHA256 per-row computation (pure function, no DB)",
		func() (int64, error) {
			if !chain.Verify(prevHash, canonical, secret, storedHash) {
				return 0, errBenchFailed
			}
			return 0, nil
		})
}

// ChainAnchorSign benchmarks Ed25519 anchor signing (per-anchor-batch operation).
func ChainAnchorSign(r *Runner) BenchResult {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	a := &chain.AnchorRecord{
		ID:         "bench-anchor",
		TableName:  "audit_logs",
		SeqLo:      1,
		SeqHi:      1000,
		RowCount:   1000,
		MerkleRoot: make([]byte, 32),
		CreatedAt:  time.Now().UTC(),
		SinkName:   "file://",
	}
	return r.Run("ChainAnchorSign",
		"chain.SignAnchor() Ed25519 signing for one anchor manifest",
		func() (int64, error) {
			return 0, chain.SignAnchor(a, priv, "bench-key-v1")
		})
}

// ChainAnchorVerify benchmarks Ed25519 anchor signature verification.
func ChainAnchorVerify(r *Runner) BenchResult {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	a := &chain.AnchorRecord{
		ID:         "bench-anchor",
		TableName:  "audit_logs",
		SeqLo:      1,
		SeqHi:      1000,
		RowCount:   1000,
		MerkleRoot: make([]byte, 32),
		CreatedAt:  time.Now().UTC(),
		SinkName:   "file://",
	}
	_ = chain.SignAnchor(a, priv, "bench-key-v1")

	return r.Run("ChainAnchorVerify",
		"chain.VerifyAnchorSignature() Ed25519 signature verification",
		func() (int64, error) {
			if !chain.VerifyAnchorSignature(a, pub) {
				return 0, errBenchFailed
			}
			return 0, nil
		})
}
