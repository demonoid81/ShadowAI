package evidencebundle

import (
	"archive/zip"
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/shadowai/backend/internal/chain"
)

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

// BundleVerifyResult is the aggregate result of all offline bundle checks.
type BundleVerifyResult struct {
	BundleDir string
	OK        bool // true only if ALL enabled checks pass

	FileIntegrity       FileIntegrityResult
	AnchorSigs          AnchorSigsResult
	SelectorManifest    SelectorManifestResult
	RangeContinuity     []RangeContinuityResult
	InventoryContinuity []InventoryContinuityResult
	InventoryCount      []InventoryCountResult
}

// FileIntegrityResult covers bundle_manifest.json file_sha256 verification.
type FileIntegrityResult struct {
	OK      bool
	Checked int
	Fails   []FileIntegrityFail
}

// FileIntegrityFail describes one hash mismatch or missing file.
type FileIntegrityFail struct {
	File     string
	Expected string
	Actual   string // empty if file is missing
	Missing  bool
}

// AnchorSigsResult covers Ed25519 signature verification across all anchors.
type AnchorSigsResult struct {
	OK       bool
	Total    int
	Unsigned int // no signature field — informational
	NoPubKey int // signature present but no pubkey provided — not verified
	Fails    []AnchorSigFail
}

// AnchorSigFail describes one anchor whose signature verification failed.
type AnchorSigFail struct {
	AnchorID string
	Table    string
	SeqLo    int64
	SeqHi    int64
}

// RangeContinuityResult covers anchor seq_lo/seq_hi continuity for one table.
// A gap means rows exist whose seq_no falls outside every anchor range.
type RangeContinuityResult struct {
	Table       string
	OK          bool
	AnchorCount int
	Gaps        []RangeGap
}

// RangeGap is a gap between two consecutive anchor ranges.
type RangeGap struct {
	PrevSeqHi int64
	NextSeqLo int64
}

// InventoryContinuityResult covers chain_inventory seq_no gap detection per table.
type InventoryContinuityResult struct {
	Table    string
	OK       bool
	RowCount int
	Gaps     []int64 // seq_no values that are missing
}

// InventoryCountResult covers anchor.RowCount vs actual inventory entries per anchor.
type InventoryCountResult struct {
	Table      string
	OK         bool
	Anchors    int
	Mismatches []InventoryCountMismatch
}

// InventoryCountMismatch describes one anchor where row_count ≠ inventory entries.
type InventoryCountMismatch struct {
	AnchorID       string
	SeqLo          int64
	SeqHi          int64
	AnchorRowCount int
	InventoryCount int
}

// ---------------------------------------------------------------------------
// OpenBundle
// ---------------------------------------------------------------------------

// OpenBundle resolves a bundle path to a local directory.
//   - If path is a directory → returns it as-is (cleanup is a no-op).
//   - If path is a .zip file → extracts to a temp dir and returns a cleanup func.
//
// The caller must call cleanup() when done to remove any temp directory.
func OpenBundle(path string) (dir string, cleanup func(), err error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", func() {}, fmt.Errorf("open bundle: %w", err)
	}
	if info.IsDir() {
		return path, func() {}, nil
	}
	// Attempt zip extraction regardless of extension — detect by magic.
	tmp, err := extractZipBundle(path)
	if err != nil {
		return "", func() {}, fmt.Errorf("open bundle zip: %w", err)
	}
	cleanup = func() { os.RemoveAll(tmp) }
	// The zip may contain a single top-level directory — descend into it.
	entries, _ := os.ReadDir(tmp)
	if len(entries) == 1 && entries[0].IsDir() {
		return filepath.Join(tmp, entries[0].Name()), cleanup, nil
	}
	return tmp, cleanup, nil
}

func extractZipBundle(zipPath string) (tmp string, retErr error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", err
	}
	defer r.Close()

	tmp, err = os.MkdirTemp("", "evidence_bundle_*")
	if err != nil {
		return "", err
	}
	// Clean up the temp dir if extraction fails for any reason.
	defer func() {
		if retErr != nil {
			os.RemoveAll(tmp)
			tmp = ""
		}
	}()

	for _, f := range r.File {
		dest := filepath.Join(tmp, filepath.Clean(f.Name))
		// Guard against zip-slip.
		if !strings.HasPrefix(dest, filepath.Clean(tmp)+string(os.PathSeparator)) {
			return tmp, fmt.Errorf("zip slip detected: %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(dest, 0o755); err != nil {
				return tmp, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return tmp, err
		}
		out, err := os.Create(dest)
		if err != nil {
			return tmp, err
		}
		rc, err := f.Open()
		if err != nil {
			out.Close()
			return tmp, err
		}
		_, copyErr := io.Copy(out, rc)
		out.Close()
		rc.Close()
		if copyErr != nil {
			return tmp, copyErr
		}
	}
	return tmp, nil
}

// ---------------------------------------------------------------------------
// VerifyBundle
// ---------------------------------------------------------------------------

// VerifyBundle runs all offline checks on a bundle directory.
//
// pubKey may be nil. If nil:
//   - anchors with signatures are counted in AnchorSigs.NoPubKey (not verified)
//   - AnchorSigs.OK = true (no pubkey → no sig check → not a failure)
//
// If pubKey is set, all anchors with signatures are verified.
// Unsigned anchors are counted in AnchorSigs.Unsigned and do not cause failure.
func VerifyBundle(dir string, pubKey ed25519.PublicKey) (BundleVerifyResult, error) {
	res := BundleVerifyResult{BundleDir: dir}

	manifest, err := readManifest(dir)
	if err != nil {
		return res, fmt.Errorf("read bundle_manifest.json: %w", err)
	}

	// 1. File integrity.
	res.FileIntegrity = checkFileIntegrity(dir, manifest.FileSHA256)

	// 2. Load anchors.
	// If file integrity failed, parsing may also fail (tampered content).
	// In that case, continue without anchors rather than returning an error —
	// the integrity failure is already captured in res.FileIntegrity.
	anchors, err := readAnchorsNDJSON(filepath.Join(dir, "anchors.jsonl"))
	if err != nil {
		if res.FileIntegrity.OK {
			return res, fmt.Errorf("read anchors.jsonl: %w", err)
		}
		anchors = nil
	}

	// 3. Load chain inventory.
	inventory, err := readInventoryNDJSON(filepath.Join(dir, "chain_inventory.jsonl"))
	if err != nil {
		if res.FileIntegrity.OK {
			return res, fmt.Errorf("read chain_inventory.jsonl: %w", err)
		}
		inventory = nil
	}

	// 4. Verify selector_manifest.jsonl if present. Missing file is OK for
	// legacy bundles; new exports always write it, even when empty.
	res.SelectorManifest = checkSelectorManifest(dir)

	// 5. Try bundle public key if caller didn't provide one.
	if len(pubKey) == 0 {
		pubKey, _ = readBundlePubKey(filepath.Join(dir, "public_key.b64"))
	}

	// 6. Anchor signature verification.
	res.AnchorSigs = checkAnchorSigs(anchors, pubKey)

	// 7. Anchor range continuity per table.
	res.RangeContinuity = checkRangeContinuity(anchors)

	// 8. Inventory seq continuity per table.
	res.InventoryContinuity = checkInventoryContinuity(inventory)

	// 9. Inventory count vs anchor row_count.
	res.InventoryCount = checkInventoryCount(anchors, inventory)

	// Overall OK: every sub-check that ran must be OK.
	res.OK = res.FileIntegrity.OK &&
		res.SelectorManifest.OK &&
		res.AnchorSigs.OK &&
		allRangeContinuityOK(res.RangeContinuity) &&
		allInventoryContinuityOK(res.InventoryContinuity) &&
		allInventoryCountOK(res.InventoryCount)

	return res, nil
}

// ---------------------------------------------------------------------------
// File integrity
// ---------------------------------------------------------------------------

func checkFileIntegrity(dir string, expected map[string]string) FileIntegrityResult {
	res := FileIntegrityResult{OK: true}
	for rel, wantHex := range expected {
		res.Checked++
		path := filepath.Join(dir, filepath.FromSlash(rel))
		got, err := FileSHA256(path)
		if err != nil {
			res.OK = false
			res.Fails = append(res.Fails, FileIntegrityFail{
				File:     rel,
				Expected: wantHex,
				Missing:  true,
			})
			continue
		}
		if got != wantHex {
			res.OK = false
			res.Fails = append(res.Fails, FileIntegrityFail{
				File:     rel,
				Expected: wantHex,
				Actual:   got,
			})
		}
	}
	return res
}

// ---------------------------------------------------------------------------
// Anchor signature check
// ---------------------------------------------------------------------------

func checkAnchorSigs(anchors []AnchorLine, pubKey ed25519.PublicKey) AnchorSigsResult {
	res := AnchorSigsResult{OK: true}
	for _, a := range anchors {
		res.Total++
		if a.SignatureHex == "" {
			res.Unsigned++
			continue
		}
		if len(pubKey) == 0 {
			res.NoPubKey++
			continue
		}
		rec := anchorLineToRecord(a)
		if !chain.VerifyAnchorSignature(&rec, pubKey) {
			res.OK = false
			res.Fails = append(res.Fails, AnchorSigFail{
				AnchorID: a.ID,
				Table:    a.Table,
				SeqLo:    a.SeqLo,
				SeqHi:    a.SeqHi,
			})
		}
	}
	return res
}

// anchorLineToRecord converts AnchorLine to chain.AnchorRecord for signature verification.
func anchorLineToRecord(a AnchorLine) chain.AnchorRecord {
	merkleRoot, _ := hex.DecodeString(a.MerkleRootHex)
	sig, _ := hex.DecodeString(a.SignatureHex)
	return chain.AnchorRecord{
		ID:         a.ID,
		TableName:  a.Table,
		SeqLo:      a.SeqLo,
		SeqHi:      a.SeqHi,
		RowCount:   a.RowCount,
		MerkleRoot: merkleRoot,
		CreatedAt:  a.CreatedAt,
		SinkName:   a.SinkName,
		SinkRef:    a.SinkRef,
		PubKeyID:   a.PubKeyID,
		Signature:  sig,
	}
}

// ---------------------------------------------------------------------------
// Anchor range continuity
// ---------------------------------------------------------------------------

func checkRangeContinuity(anchors []AnchorLine) []RangeContinuityResult {
	byTable := groupAnchorsByTable(anchors)
	var results []RangeContinuityResult
	for _, table := range sortedKeys(byTable) {
		tableAnchors := byTable[table]
		sort.Slice(tableAnchors, func(i, j int) bool {
			return tableAnchors[i].SeqLo < tableAnchors[j].SeqLo
		})
		r := RangeContinuityResult{
			Table:       table,
			OK:          true,
			AnchorCount: len(tableAnchors),
		}
		for i := 1; i < len(tableAnchors); i++ {
			prev := tableAnchors[i-1]
			curr := tableAnchors[i]
			// Anchors use inclusive ranges [SeqLo, SeqHi].
			// The scheduler stores SeqLo = prevAnchor.SeqHi + 1.
			// Consecutive anchors without a gap satisfy: curr.SeqLo == prev.SeqHi + 1.
			if curr.SeqLo != prev.SeqHi+1 {
				r.OK = false
				r.Gaps = append(r.Gaps, RangeGap{
					PrevSeqHi: prev.SeqHi,
					NextSeqLo: curr.SeqLo,
				})
			}
		}
		results = append(results, r)
	}
	return results
}

// ---------------------------------------------------------------------------
// Inventory continuity
// ---------------------------------------------------------------------------

func checkInventoryContinuity(inventory []ChainInventoryLine) []InventoryContinuityResult {
	byTable := groupInventoryByTable(inventory)
	var results []InventoryContinuityResult
	for _, table := range sortedKeys(byTable) {
		rows := byTable[table]
		sort.Slice(rows, func(i, j int) bool { return rows[i].SeqNo < rows[j].SeqNo })
		r := InventoryContinuityResult{
			Table:    table,
			OK:       true,
			RowCount: len(rows),
		}
		for i := 1; i < len(rows); i++ {
			if rows[i].SeqNo != rows[i-1].SeqNo+1 {
				r.OK = false
				for gap := rows[i-1].SeqNo + 1; gap < rows[i].SeqNo; gap++ {
					r.Gaps = append(r.Gaps, gap)
				}
			}
		}
		results = append(results, r)
	}
	return results
}

// ---------------------------------------------------------------------------
// Inventory count vs anchor row_count
// ---------------------------------------------------------------------------

func checkInventoryCount(anchors []AnchorLine, inventory []ChainInventoryLine) []InventoryCountResult {
	// Build per-table inventory index: seqNo → present.
	invByTable := make(map[string][]int64)
	for _, row := range inventory {
		invByTable[row.Table] = append(invByTable[row.Table], row.SeqNo)
	}
	// Sort for binary search.
	for t := range invByTable {
		sort.Slice(invByTable[t], func(i, j int) bool { return invByTable[t][i] < invByTable[t][j] })
	}

	byTable := groupAnchorsByTable(anchors)
	var results []InventoryCountResult
	for _, table := range sortedKeys(byTable) {
		tableAnchors := byTable[table]
		seqNos := invByTable[table]
		r := InventoryCountResult{
			Table:   table,
			OK:      true,
			Anchors: len(tableAnchors),
		}
		for _, a := range tableAnchors {
			// Count inventory entries in inclusive range [SeqLo, SeqHi].
			count := countInRange(seqNos, a.SeqLo, a.SeqHi)
			if count != a.RowCount {
				r.OK = false
				r.Mismatches = append(r.Mismatches, InventoryCountMismatch{
					AnchorID:       a.ID,
					SeqLo:          a.SeqLo,
					SeqHi:          a.SeqHi,
					AnchorRowCount: a.RowCount,
					InventoryCount: count,
				})
			}
		}
		results = append(results, r)
	}
	return results
}

// countInRange counts elements in sorted slice where lo <= v <= hi (inclusive).
// Anchors use inclusive [SeqLo, SeqHi] ranges (scheduler stores SeqLo = lastSeqHi+1).
func countInRange(sorted []int64, lo, hi int64) int {
	if len(sorted) == 0 {
		return 0
	}
	// Find first index where v >= lo (inclusive lower bound).
	loIdx := sort.Search(len(sorted), func(i int) bool { return sorted[i] >= lo })
	// Find first index where v > hi.
	hiIdx := sort.Search(len(sorted), func(i int) bool { return sorted[i] > hi })
	return hiIdx - loIdx
}

// ---------------------------------------------------------------------------
// NDJSON readers
// ---------------------------------------------------------------------------

// ReadBundleManifest is the exported version of readManifest for CLI dispatch.
func ReadBundleManifest(dir string) (*BundleManifest, error) {
	return readManifest(dir)
}

// LoadBundlePublicKey loads public_key.b64 from the bundle directory.
// Returns nil, nil when the file is absent (unsigned bundle).
func LoadBundlePublicKey(dir string) (ed25519.PublicKey, error) {
	return readBundlePubKey(filepath.Join(dir, "public_key.b64"))
}

func readManifest(dir string) (*BundleManifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, "bundle_manifest.json"))
	if err != nil {
		return nil, err
	}
	var m BundleManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func readAnchorsNDJSON(path string) ([]AnchorLine, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var result []AnchorLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var a AnchorLine
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			return nil, fmt.Errorf("anchors.jsonl: parse: %w", err)
		}
		result = append(result, a)
	}
	return result, sc.Err()
}

func readInventoryNDJSON(path string) ([]ChainInventoryLine, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var result []ChainInventoryLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var inv ChainInventoryLine
		if err := json.Unmarshal([]byte(line), &inv); err != nil {
			return nil, fmt.Errorf("chain_inventory.jsonl: parse: %w", err)
		}
		result = append(result, inv)
	}
	return result, sc.Err()
}

func readBundlePubKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return chain.ParsePublicKey(strings.TrimSpace(string(data)))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func groupAnchorsByTable(anchors []AnchorLine) map[string][]AnchorLine {
	m := make(map[string][]AnchorLine)
	for _, a := range anchors {
		m[a.Table] = append(m[a.Table], a)
	}
	return m
}

func groupInventoryByTable(inventory []ChainInventoryLine) map[string][]ChainInventoryLine {
	m := make(map[string][]ChainInventoryLine)
	for _, row := range inventory {
		m[row.Table] = append(m[row.Table], row)
	}
	return m
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func allRangeContinuityOK(rs []RangeContinuityResult) bool {
	for _, r := range rs {
		if !r.OK {
			return false
		}
	}
	return true
}

func allInventoryContinuityOK(rs []InventoryContinuityResult) bool {
	for _, r := range rs {
		if !r.OK {
			return false
		}
	}
	return true
}

func allInventoryCountOK(rs []InventoryCountResult) bool {
	for _, r := range rs {
		if !r.OK {
			return false
		}
	}
	return true
}
