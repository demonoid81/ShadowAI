package evidencebundle

import "github.com/shadowai/backend/internal/chain"

// TenantChainHashLine is one entry in tenant_chain_hashes.jsonl.
// Contains only rows belonging to the export's org — no cross-tenant hashes.
type TenantChainHashLine struct {
	Table      string `json:"table"`
	SeqNo      int64  `json:"seq_no"`
	RowIDHash  string `json:"row_id_hash"`  // SHA256(row_id) — stable identifier
	RowHashHex string `json:"row_hash_hex"` // stored HMAC chain hash (the Merkle leaf)
}

// MerkleProofLine is one entry in merkle_proofs.jsonl.
// The verifier uses LeafHashHex + Siblings to reconstruct RootHex and compare
// with the signed anchor's merkle_root_hex.
type MerkleProofLine struct {
	Table       string                     `json:"table"`
	SeqNo       int64                      `json:"seq_no"`
	AnchorSeqLo int64                      `json:"anchor_seq_lo"`
	AnchorSeqHi int64                      `json:"anchor_seq_hi"`
	LeafHashHex string                     `json:"leaf_hash_hex"`
	Siblings    []chain.MerkleProofSibling `json:"siblings"`
	RootHex     string                     `json:"root_hex"` // expected root; must match anchor
}

// TenantVerifyResult holds the outcome of an offline tenant bundle verification.
type TenantVerifyResult struct {
	OK               bool
	ProofsChecked    int
	ProofsFailed     []TenantProofFailure
	SignaturesFailed []string // anchor IDs whose Ed25519 signature didn't verify
	SelectorManifest SelectorManifestResult
}

// TenantProofFailure describes one failed inclusion proof.
type TenantProofFailure struct {
	Table  string
	SeqNo  int64
	Reason string
}
