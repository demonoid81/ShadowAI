// manifest.go — package manifest types and SHA256 computation for SOC2.1.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// computeSHA256 returns the raw SHA256 digest of data.
func computeSHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// pkgSchemaVersion is the manifest format version. Increment on breaking changes.
const pkgSchemaVersion = "1"

// ControlStatus describes the collection status of a single control artifact.
type ControlStatus string

const (
	// ControlCollected — artifact collected and included in the package.
	ControlCollected ControlStatus = "collected"
	// ControlTemplate — template file generated; operator must fill in details.
	ControlTemplate ControlStatus = "template"
	// ControlNotCollected — could not collect; reason in Reason field.
	ControlNotCollected ControlStatus = "not_collected"
)

// ControlEntry describes one control evidence item in the manifest.
type ControlEntry struct {
	ID                string        `json:"id"`
	Description       string        `json:"description"`
	Status            ControlStatus `json:"status"`
	File              string        `json:"file,omitempty"`
	Summary           string        `json:"summary,omitempty"`
	LiveCheckRequired bool          `json:"live_check_required,omitempty"`
	Reason            string        `json:"reason,omitempty"` // for not_collected
}

// Period is the audit evidence collection window.
type Period struct {
	From string `json:"from"` // YYYY-MM-DD
	To   string `json:"to"`   // YYYY-MM-DD
}

// PackageManifest is the root manifest written as manifest.json.
type PackageManifest struct {
	SchemaVersion string            `json:"schema_version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	Generator     string            `json:"generator"`
	BuildCommit   string            `json:"build_commit,omitempty"`
	Period        Period            `json:"period"`
	Controls      []ControlEntry    `json:"controls"`
	FileSHA256    map[string]string `json:"file_sha256"`
}

// addControl appends a control entry to the manifest.
func (m *PackageManifest) addControl(e ControlEntry) {
	m.Controls = append(m.Controls, e)
}

// computeFileSHA256 walks the output directory and computes SHA256 for every
// file except manifest.json itself (which is written last).
func computeFileSHA256(dir string) (map[string]string, error) {
	hashes := make(map[string]string)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "manifest.json" {
			return nil // skip manifest itself
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		h := sha256.Sum256(data)
		const hexChars = "0123456789abcdef"
		hex := make([]byte, len(h)*2)
		for i, b := range h {
			hex[i*2] = hexChars[b>>4]
			hex[i*2+1] = hexChars[b&0xf]
		}
		hashes[rel] = string(hex)
		return nil
	})
	return hashes, err
}

// writeManifest serialises m as indented JSON to <dir>/manifest.json.
func writeManifest(dir string, m *PackageManifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o644)
}
