// multi_sink.go — W8: multi-sink anchor publication types and optional repo interface.
package chain

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// AnchorSinkResult records the result of writing an anchor manifest to one sink.
// Used for per-sink visibility in audit_chain_anchor_sinks.
type AnchorSinkResult struct {
	SinkName  string    `json:"sink_name"`
	SinkRef   string    `json:"sink_ref"`
	SinkOK    bool      `json:"sink_ok"`
	ErrorMsg  string    `json:"error_msg,omitempty"` // non-empty when SinkOK=false
	WrittenAt time.Time `json:"written_at"`
}

// AnchorSinksWriter is an optional interface that AnchorRepoReader implementations
// may satisfy to support multi-sink write recording (W8).
//
// If the repo does NOT implement this interface, additional sink results are logged
// but not persisted — backward-compatible degraded behavior.
type AnchorSinksWriter interface {
	// WriteAnchorSinks records per-sink write results for a multi-sink anchor.
	// Called after WriteAnchor has set a.ID.
	WriteAnchorSinks(ctx context.Context, anchorID string, results []AnchorSinkResult) error

	// ListAnchorSinks returns the recorded sink results for an anchor.
	// Returns empty slice if anchorID has no additional sinks (legacy/single-sink).
	ListAnchorSinks(ctx context.Context, anchorID string) ([]AnchorSinkResult, error)
}

// WriteAnchorSinks writes per-sink records to audit_chain_anchor_sinks.
// Part of AnchorRepository; satisfies AnchorSinksWriter.
func (r *AnchorRepository) WriteAnchorSinks(ctx context.Context, anchorID string, results []AnchorSinkResult) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("anchor sinks: repo not configured")
	}
	for _, res := range results {
		var errMsg interface{}
		if res.ErrorMsg != "" {
			errMsg = res.ErrorMsg
		}
		_, err := r.db.ExecContext(ctx,
			`INSERT INTO audit_chain_anchor_sinks (anchor_id, sink_name, sink_ref, sink_ok, error_msg, written_at)
			 VALUES ($1, $2, $3, $4, $5, $6)
			 ON CONFLICT (anchor_id, sink_name) DO UPDATE
			 SET sink_ref = EXCLUDED.sink_ref, sink_ok = EXCLUDED.sink_ok,
			     error_msg = EXCLUDED.error_msg, written_at = EXCLUDED.written_at`,
			anchorID, res.SinkName, res.SinkRef, res.SinkOK, errMsg, res.WrittenAt,
		)
		if err != nil {
			return fmt.Errorf("anchor sinks: write %s: %w", res.SinkName, err)
		}
	}
	return nil
}

// ListAnchorSinks returns recorded sink results for an anchor.
// Empty slice means no additional sinks recorded (legacy/single-sink anchor).
func (r *AnchorRepository) ListAnchorSinks(ctx context.Context, anchorID string) ([]AnchorSinkResult, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("anchor sinks: repo not configured")
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT sink_name, sink_ref, sink_ok, coalesce(error_msg,''), written_at
		 FROM audit_chain_anchor_sinks WHERE anchor_id = $1
		 ORDER BY sink_name`, anchorID)
	if err != nil {
		return nil, fmt.Errorf("anchor sinks: list for %s: %w", anchorID, err)
	}
	defer rows.Close()
	var results []AnchorSinkResult
	for rows.Next() {
		var r AnchorSinkResult
		if err := rows.Scan(&r.SinkName, &r.SinkRef, &r.SinkOK, &r.ErrorMsg, &r.WrittenAt); err != nil {
			return nil, fmt.Errorf("anchor sinks: scan: %w", err)
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

// writeAdditionalSinks writes the pre-signed manifest to all additional sinks
// and records the results. Called by anchorTable after WriteAnchor.
//
// Partial failure: if any sink write fails, that result has SinkOK=false with
// ErrorMsg set. The function logs each failure and returns the results; it does
// NOT abort on first failure (fail-visible, not fail-fast).
func writeAdditionalSinks(
	ctx context.Context,
	sinks []AnchorSink,
	a *AnchorRecord,
	manifest []byte,
) []AnchorSinkResult {
	results := make([]AnchorSinkResult, 0, len(sinks))
	for _, s := range sinks {
		ref := s.BuildRef(a)
		err := s.Write(ctx, manifest, ref)
		res := AnchorSinkResult{
			SinkName:  s.Name(),
			SinkRef:   ref,
			SinkOK:    err == nil,
			WrittenAt: time.Now().UTC(),
		}
		if err != nil {
			res.ErrorMsg = err.Error()
			log.Printf("anchor: PARTIAL SINK FAILURE table=%s seq=[%d,%d] sink=%s err=%v",
				a.TableName, a.SeqLo, a.SeqHi, s.Name(), err)
		}
		results = append(results, res)
	}
	return results
}

// MultiSinkVerifyResult is the result of verifying additional sink records.
type MultiSinkVerifyResult struct {
	AnchorID      string
	Table         string
	SeqLo, SeqHi  int64
	SinkResults   []SinkVerifyDetail
	AllOK         bool
	MissingCount  int
	MismatchCount int
}

// SinkVerifyDetail describes verification of one additional sink.
type SinkVerifyDetail struct {
	AnchorID      string `json:"anchor_id,omitempty"`
	Table         string `json:"table,omitempty"`
	SeqLo         int64  `json:"seq_lo,omitempty"`
	SeqHi         int64  `json:"seq_hi,omitempty"`
	SinkName      string `json:"sink_name"`
	SinkRef       string `json:"sink_ref"`
	RecordedOK    bool   `json:"recorded_ok"`    // what the DB says sink_ok was at write time
	ManifestMatch bool   `json:"manifest_match"` // true if re-read manifest matches DB manifest
	Status        string `json:"status"`         // "ok" | "missing" | "mismatch" | "unverified"
	Reason        string `json:"reason,omitempty"`
}

// AdditionalSinksVerifyResult is the table-level result of re-reading W8
// additional sink records and checking that every recorded sink still contains
// the signed manifest for its anchor.
type AdditionalSinksVerifyResult struct {
	Table       string
	AnchorCount int
	SinkCount   int
	OKCount     int
	Failures    []SinkVerifyDetail
	OK          bool
}

// VerifyAnchorAdditionalFileSinks verifies file:// additional sinks only.
// It is safe to call from --include-anchors / --anchor-only because it does not
// require external credentials. immudb:// rows are left to --verify-sink.
func VerifyAnchorAdditionalFileSinks(ctx context.Context, db *sql.DB, tableName string, pubKey ed25519.PublicKey) (AdditionalSinksVerifyResult, error) {
	return VerifyAnchorAdditionalFileSinksWithKeyring(ctx, db, tableName, signingKeyringFromPubKey(pubKey))
}

// VerifyAnchorAdditionalFileSinksWithKeyring is the W7 keyring-aware variant
// of VerifyAnchorAdditionalFileSinks.
func VerifyAnchorAdditionalFileSinksWithKeyring(ctx context.Context, db *sql.DB, tableName string, keyring *SigningKeyring) (AdditionalSinksVerifyResult, error) {
	return verifyAnchorAdditionalSinks(ctx, db, tableName, nil, keyring, false)
}

// VerifyAnchorAdditionalSinks verifies all W8 additional sink rows. immudb://
// rows require an ImmuDBSink instance; file:// rows are verified directly from
// their sink_ref path.
func VerifyAnchorAdditionalSinks(ctx context.Context, db *sql.DB, tableName string, immuSink *ImmuDBSink, pubKey ed25519.PublicKey) (AdditionalSinksVerifyResult, error) {
	return VerifyAnchorAdditionalSinksWithKeyring(ctx, db, tableName, immuSink, signingKeyringFromPubKey(pubKey))
}

// VerifyAnchorAdditionalSinksWithKeyring verifies all W8 additional sink rows
// with W7 signing key rotation support.
func VerifyAnchorAdditionalSinksWithKeyring(ctx context.Context, db *sql.DB, tableName string, immuSink *ImmuDBSink, keyring *SigningKeyring) (AdditionalSinksVerifyResult, error) {
	return verifyAnchorAdditionalSinks(ctx, db, tableName, immuSink, keyring, true)
}

func verifyAnchorAdditionalSinks(ctx context.Context, db *sql.DB, tableName string, immuSink *ImmuDBSink, keyring *SigningKeyring, includeImmu bool) (AdditionalSinksVerifyResult, error) {
	res := AdditionalSinksVerifyResult{Table: tableName}
	repo := NewAnchorRepository(db)
	anchors, err := repo.ListAnchors(ctx, tableName)
	if err != nil {
		return res, fmt.Errorf("verify additional sinks %s: list anchors: %w", tableName, err)
	}
	res.AnchorCount = len(anchors)

	for _, a := range anchors {
		sinks, err := repo.ListAnchorSinks(ctx, a.ID)
		if err != nil {
			if anchorSinksTableMissing(err) {
				res.OK = true
				return res, nil
			}
			return res, fmt.Errorf("verify additional sinks %s: list anchor_sinks %s: %w", tableName, a.ID, err)
		}
		for _, s := range sinks {
			if s.SinkName == "immudb://" && !includeImmu {
				continue
			}
			res.SinkCount++
			detail := SinkVerifyDetail{
				AnchorID:   a.ID,
				Table:      a.TableName,
				SeqLo:      a.SeqLo,
				SeqHi:      a.SeqHi,
				SinkName:   s.SinkName,
				SinkRef:    s.SinkRef,
				RecordedOK: s.SinkOK,
			}
			if !s.SinkOK {
				detail.Status = "recorded_failure"
				detail.Reason = s.ErrorMsg
				res.Failures = append(res.Failures, detail)
				continue
			}

			var ok bool
			switch s.SinkName {
			case "file://":
				path := strings.TrimPrefix(s.SinkRef, "file://")
				if path == "" {
					detail.Status = "missing"
					detail.Reason = "empty file sink_ref"
					res.Failures = append(res.Failures, detail)
					continue
				}
				ok, err = verifyFileSinkManifest(path, &a, keyring)
			case "immudb://":
				if immuSink == nil {
					detail.Status = "unverified"
					detail.Reason = "immudb verifier not configured"
					res.Failures = append(res.Failures, detail)
					continue
				}
				if gotRef := immuSink.BuildRef(&a); gotRef != s.SinkRef {
					detail.Status = "mismatch"
					detail.Reason = fmt.Sprintf("recorded sink_ref %q != verifier ref %q", s.SinkRef, gotRef)
					res.Failures = append(res.Failures, detail)
					continue
				}
				ok, err = VerifyImmuDBSinkRecordWithKeyring(ctx, immuSink, &a, keyring)
			default:
				detail.Status = "unverified"
				detail.Reason = fmt.Sprintf("unsupported sink %q", s.SinkName)
				res.Failures = append(res.Failures, detail)
				continue
			}
			if err != nil {
				detail.Status = "missing"
				detail.Reason = err.Error()
				res.Failures = append(res.Failures, detail)
				continue
			}
			if !ok {
				detail.Status = "mismatch"
				detail.Reason = "manifest does not match DB anchor"
				res.Failures = append(res.Failures, detail)
				continue
			}
			detail.Status = "ok"
			detail.ManifestMatch = true
			res.OKCount++
		}
	}
	res.OK = len(res.Failures) == 0
	return res, nil
}

func anchorSinksTableMissing(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "audit_chain_anchor_sinks") &&
		(strings.Contains(msg, "does not exist") || strings.Contains(msg, "undefined table"))
}

// verifyFileSinkManifest re-reads manifest from a file:// sink and checks that
// the exact anchor manifest is present and matches the DB anchor fields.
func verifyFileSinkManifest(path string, expected *AnchorRecord, keyring *SigningKeyring) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("read file sink: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		manifest, err := UnmarshalSignedManifest(line)
		if err != nil {
			return false, fmt.Errorf("parse file sink manifest: %w", err)
		}
		if manifest.TableName != expected.TableName ||
			manifest.SeqLo != expected.SeqLo ||
			manifest.SeqHi != expected.SeqHi {
			continue
		}
		return manifestMatchesAnchor(manifest, expected, keyring), nil
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("scan file sink: %w", err)
	}
	return false, nil
}

func manifestMatchesAnchor(manifest, expected *AnchorRecord, keyring *SigningKeyring) bool {
	if manifest.TableName != expected.TableName ||
		manifest.SeqLo != expected.SeqLo ||
		manifest.SeqHi != expected.SeqHi ||
		manifest.RowCount != expected.RowCount ||
		manifest.SinkName != expected.SinkName ||
		manifest.SinkRef != expected.SinkRef ||
		manifest.PubKeyID != expected.PubKeyID ||
		manifest.CreatedAt.UTC().Unix() != expected.CreatedAt.UTC().Unix() ||
		!merkleEqual(manifest.MerkleRoot, expected.MerkleRoot) ||
		!bytes.Equal(manifest.Signature, expected.Signature) {
		return false
	}
	return verifyAnchorSignatureWithKeyring(manifest, keyring)
}

func signingKeyringFromPubKey(pubKey ed25519.PublicKey) *SigningKeyring {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil
	}
	return SingleKeyKeyring(pubKey)
}

func verifyAnchorSignatureWithKeyring(a *AnchorRecord, keyring *SigningKeyring) bool {
	if keyring == nil {
		return true
	}
	pub, ok := keyring.LookupSigningKey(a.PubKeyID)
	if !ok {
		return false
	}
	return VerifyAnchorSignature(a, pub)
}
