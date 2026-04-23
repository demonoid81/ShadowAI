package chain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// SignedManifestV1 — wire format для anchor manifest в external sinks.
//
// Формат версионирован (V=1). Поля совпадают с ManifestCanonical,
// но сериализованы как JSON для human-readability и cross-tool compatibility.
//
// signature_hex покрывает canonical payload (ManifestCanonical),
// который включает sink_ref — так что signature is over the final
// deterministic ref, not a temporary placeholder.
type SignedManifestV1 struct {
	V             int    `json:"v"`
	Table         string `json:"table"`
	SeqLo         int64  `json:"seq_lo"`
	SeqHi         int64  `json:"seq_hi"`
	RowCount      int    `json:"row_count"`
	MerkleRootHex string `json:"merkle_root_hex"`
	CreatedAt     string `json:"created_at"` // RFC3339 UTC
	SinkName      string `json:"sink_name"`
	SinkRef       string `json:"sink_ref"`
	PubKeyID      string `json:"pubkey_id,omitempty"`
	SignatureHex  string `json:"signature_hex,omitempty"`
}

// MarshalSignedManifest serializes an AnchorRecord to manifest JSON bytes.
// PubKeyID and Signature are included only if set.
func MarshalSignedManifest(a *AnchorRecord) ([]byte, error) {
	m := SignedManifestV1{
		V:             1,
		Table:         a.TableName,
		SeqLo:         a.SeqLo,
		SeqHi:         a.SeqHi,
		RowCount:      a.RowCount,
		MerkleRootHex: hex.EncodeToString(a.MerkleRoot),
		CreatedAt:     a.CreatedAt.UTC().Format(time.RFC3339),
		SinkName:      a.SinkName,
		SinkRef:       a.SinkRef,
		PubKeyID:      a.PubKeyID,
	}
	if len(a.Signature) > 0 {
		m.SignatureHex = hex.EncodeToString(a.Signature)
	}
	return json.Marshal(m)
}

// UnmarshalSignedManifest deserializes manifest JSON into an AnchorRecord.
// Used by verifier to cross-check sink payload against DB anchor.
func UnmarshalSignedManifest(data []byte) (*AnchorRecord, error) {
	var m SignedManifestV1
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest: unmarshal: %w", err)
	}
	if m.V != 1 {
		return nil, fmt.Errorf("manifest: unsupported version %d", m.V)
	}
	merkleRoot, err := hexToBytes(m.MerkleRootHex)
	if err != nil {
		return nil, fmt.Errorf("manifest: merkle_root_hex: %w", err)
	}
	createdAt, err := time.Parse(time.RFC3339, m.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("manifest: created_at: %w", err)
	}
	a := &AnchorRecord{
		TableName:  m.Table,
		SeqLo:      m.SeqLo,
		SeqHi:      m.SeqHi,
		RowCount:   m.RowCount,
		MerkleRoot: merkleRoot,
		CreatedAt:  createdAt.UTC(),
		SinkName:   m.SinkName,
		SinkRef:    m.SinkRef,
		PubKeyID:   m.PubKeyID,
	}
	if m.SignatureHex != "" {
		sig, err := hexToBytes(m.SignatureHex)
		if err != nil {
			return nil, fmt.Errorf("manifest: signature_hex: %w", err)
		}
		a.Signature = sig
	}
	return a, nil
}
