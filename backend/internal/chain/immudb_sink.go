package chain

import (
	"context"
	"crypto/ed25519"
	"fmt"
)

// ImmuDBClient — thin interface over immudb operations needed by ImmuDBSink.
// Concrete implementation uses github.com/codenotary/immudb/pkg/client.
// Tests use MockImmuDBClient.
//
// To connect to real immudb:
//   import (
//       immudb "github.com/codenotary/immudb/pkg/client"
//       schema "github.com/codenotary/immudb/pkg/api/schema"
//   )
//   client, _ := immudb.NewImmuClient(immudb.DefaultOptions().WithAddress(addr))
//   client.Login(ctx, []byte(user), []byte(pass))
//   client.UseDatabase(ctx, &schema.Database{DatabaseName: db})
//   impl := &RealImmuDBClient{client: client}
//   sink := NewImmuDBSink(impl, database)
type ImmuDBClient interface {
	// Set stores value under key. Returns the transaction ID.
	Set(ctx context.Context, key string, value []byte) (txID uint64, err error)
	// Get retrieves value by key.
	Get(ctx context.Context, key string) ([]byte, error)
}

// ImmuDBSink — immudb:// AnchorSink. Stores signed manifest JSON under
// a deterministic key in immudb's append-only store.
//
// immudb key format: shadowai/anchors/<table>/<seq_lo>-<seq_hi>
// sink_ref format:   immudb://<database>/<table>/<seq_lo>-<seq_hi>
//
// sink_ref is deterministic (built without tx ID) so that it is covered
// by the Ed25519 signature before Write() is called.
type ImmuDBSink struct {
	client   ImmuDBClient
	database string
}

// NewImmuDBSink creates an ImmuDBSink with the given client and database name.
func NewImmuDBSink(client ImmuDBClient, database string) *ImmuDBSink {
	return &ImmuDBSink{client: client, database: database}
}

func (s *ImmuDBSink) Name() string { return "immudb://" }

// BuildRef returns "immudb://<database>/<table>/<seq_lo>-<seq_hi>".
// Deterministic: no I/O, same value every call for same anchor.
func (s *ImmuDBSink) BuildRef(a *AnchorRecord) string {
	return fmt.Sprintf("immudb://%s/%s/%d-%d",
		s.database, a.TableName, a.SeqLo, a.SeqHi)
}

// Write stores manifest bytes under the deterministic immudb key.
// ref is the BuildRef output; key is derived from it.
func (s *ImmuDBSink) Write(ctx context.Context, manifest []byte, ref string) error {
	key := immudbKeyFromRef(ref)
	if key == "" {
		return fmt.Errorf("immudb sink: cannot derive key from ref %q", ref)
	}
	if _, err := s.client.Set(ctx, key, manifest); err != nil {
		return fmt.Errorf("immudb sink: set %s: %w", key, err)
	}
	return nil
}

// ReadManifest fetches the stored manifest from immudb for the given AnchorRecord.
// Used by verifier to cross-check sink payload against DB anchor.
func (s *ImmuDBSink) ReadManifest(ctx context.Context, a *AnchorRecord) ([]byte, error) {
	ref := s.BuildRef(a)
	key := immudbKeyFromRef(ref)
	data, err := s.client.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("immudb sink: get %s: %w", key, err)
	}
	return data, nil
}

// immudbKeyFromRef derives "shadowai/anchors/<table>/<seq_lo>-<seq_hi>"
// from "immudb://<database>/<table>/<seq_lo>-<seq_hi>".
func immudbKeyFromRef(ref string) string {
	// ref = "immudb://<db>/<table>/<seq_lo>-<seq_hi>"
	// Strip "immudb://".
	if len(ref) < len("immudb://") {
		return ""
	}
	rest := ref[len("immudb://"):]
	// rest = "<db>/<table>/<seq_lo>-<seq_hi>"
	// Find first slash to skip db name.
	idx := findByte(rest, '/')
	if idx < 0 {
		return ""
	}
	// path = "<table>/<seq_lo>-<seq_hi>"
	path := rest[idx+1:]
	return "shadowai/anchors/" + path
}

func findByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// VerifyImmuDBSinkRecord fetches the manifest from immudb and verifies:
//  1. All manifest fields match the DB anchor record (including sink_name,
//     sink_ref, pubkey_id, created_at epoch).
//  2. If pubKey is non-nil: signature must be present AND valid. An unsigned
//     manifest fails when pubKey is set — prevents downgrade to unsigned.
//
// Returns (true, nil) if everything matches. (false, nil) for any field
// mismatch or signature failure. (false, err) for network/parse errors.
func VerifyImmuDBSinkRecord(ctx context.Context, sink *ImmuDBSink, a *AnchorRecord, pubKey ed25519.PublicKey) (bool, error) {
	if sink == nil {
		return false, nil
	}
	data, err := sink.ReadManifest(ctx, a)
	if err != nil {
		return false, err
	}
	manifest, err := UnmarshalSignedManifest(data)
	if err != nil {
		return false, fmt.Errorf("verify immudb: unmarshal: %w", err)
	}
	// Field comparison — all evidence fields must match exactly.
	if manifest.TableName != a.TableName ||
		manifest.SeqLo != a.SeqLo ||
		manifest.SeqHi != a.SeqHi ||
		manifest.RowCount != a.RowCount ||
		manifest.SinkName != a.SinkName ||
		manifest.SinkRef != a.SinkRef ||
		manifest.PubKeyID != a.PubKeyID ||
		manifest.CreatedAt.UTC().Unix() != a.CreatedAt.UTC().Unix() ||
		!merkleEqual(manifest.MerkleRoot, a.MerkleRoot) {
		return false, nil
	}
	// Signature verification.
	if len(pubKey) == ed25519.PublicKeySize {
		// If pubKey provided: signature must be present (unsigned = fail).
		// Prevents downgrade: a DBA who re-signs with a different key or
		// strips the signature cannot pass verification.
		if len(manifest.Signature) == 0 {
			return false, nil // unsigned manifest when pubKey is set
		}
		if !VerifyAnchorSignature(manifest, pubKey) {
			return false, nil
		}
	}
	return true, nil
}
