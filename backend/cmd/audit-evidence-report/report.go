// report.go — S3 data collection and compliance evaluation for O4.4.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// BundleRecord holds S3 and Object Lock metadata for one evidence bundle zip.
type BundleRecord struct {
	Key          string     `json:"key"`
	BundleType   string     `json:"bundle_type"` // "global" | "tenant" | "unknown"
	OrgID        string     `json:"org_id"`
	SizeBytes    int64      `json:"size_bytes"`
	ETag         string     `json:"etag"`
	LastModified time.Time  `json:"last_modified"`
	LockMode     string     `json:"lock_mode,omitempty"`    // "COMPLIANCE" | "GOVERNANCE"
	RetainUntil  *time.Time `json:"retain_until,omitempty"` // nil when Object Lock not set
	LegalHold    string     `json:"legal_hold,omitempty"`   // "ON" | "OFF"

	// Populated when --read-manifest is set.
	ManifestOrgID      string     `json:"manifest_org_id,omitempty"`
	ManifestTables     []string   `json:"manifest_tables,omitempty"`
	ManifestExportTime *time.Time `json:"manifest_export_time,omitempty"`

	Compliant  bool     `json:"compliant"`
	Violations []string `json:"violations,omitempty"`
}

// Report is the full retention audit report.
type Report struct {
	GeneratedAt      time.Time      `json:"generated_at"`
	Bucket           string         `json:"bucket"`
	Prefix           string         `json:"prefix"`
	AfterFilter      string         `json:"after_filter,omitempty"`
	BeforeFilter     string         `json:"before_filter,omitempty"`
	RequireLock      bool           `json:"require_lock"`
	MinRetentionDays int            `json:"min_retention_days"`
	TotalBundles     int            `json:"total_bundles"`
	CompliantCount   int            `json:"compliant_count"`
	ViolationCount   int            `json:"violation_count"`
	Bundles          []BundleRecord `json:"bundles"`
}

// tenantKeyRe matches tenant bundle names: tenant-<uuid>-YYYYMMDD-HHMMSS.zip
var tenantKeyRe = regexp.MustCompile(
	`tenant-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})-\d{8}`,
)

// parseKeyInfo extracts bundle_type and org_id from an S3 object key.
// Inference is based on the file name; no download required.
func parseKeyInfo(key string) (bundleType, orgID string) {
	base := path.Base(key)
	if m := tenantKeyRe.FindStringSubmatch(base); m != nil {
		return "tenant", m[1]
	}
	if strings.HasPrefix(base, "global-") {
		return "global", ""
	}
	return "unknown", ""
}

// checkCompliance sets Compliant and Violations on rec based on the policy.
func checkCompliance(rec *BundleRecord, requireLock bool, minRetentionDays int) {
	now := time.Now().UTC()
	rec.Violations = nil

	if requireLock && rec.LockMode == "" {
		rec.Violations = append(rec.Violations, "missing_object_lock")
	}
	if rec.RetainUntil != nil {
		if rec.RetainUntil.Before(now) {
			rec.Violations = append(rec.Violations,
				fmt.Sprintf("lock_expired(since=%s)", rec.RetainUntil.Format("2006-01-02")))
		} else if minRetentionDays > 0 {
			minDate := now.Add(time.Duration(minRetentionDays) * 24 * time.Hour)
			if rec.RetainUntil.Before(minDate) {
				rec.Violations = append(rec.Violations,
					fmt.Sprintf("retention_too_short(retain_until=%s,need_days=%d)",
						rec.RetainUntil.Format("2006-01-02"), minRetentionDays))
			}
		}
	}

	rec.Compliant = len(rec.Violations) == 0
}

// collectBundles pages through S3, calls HeadObject per .zip, evaluates compliance.
func collectBundles(
	ctx context.Context,
	client *s3.Client,
	bucket, prefix string,
	afterFilter, beforeFilter *time.Time,
	requireLock bool,
	minRetentionDays int,
	readManifestFlag bool,
) ([]BundleRecord, error) {
	var records []BundleRecord

	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list objects: %w", err)
		}
		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			if !strings.HasSuffix(key, ".zip") {
				continue
			}
			if obj.LastModified != nil {
				if afterFilter != nil && obj.LastModified.Before(*afterFilter) {
					continue
				}
				if beforeFilter != nil && obj.LastModified.After(*beforeFilter) {
					continue
				}
			}

			rec, err := headBundle(ctx, client, bucket, key, obj)
			if err != nil {
				return nil, fmt.Errorf("head %s: %w", key, err)
			}

			if readManifestFlag {
				if err := fetchManifest(ctx, client, bucket, &rec); err != nil {
					// Non-fatal: record the error as a soft violation.
					rec.Violations = append(rec.Violations,
						fmt.Sprintf("manifest_read_error(%v)", err))
				}
			}

			checkCompliance(&rec, requireLock, minRetentionDays)
			records = append(records, rec)
		}
	}
	return records, nil
}

// headBundle issues HeadObject and builds a BundleRecord.
// listObj is accepted to keep the call site symmetrical with ListObjectsV2 Contents
// but HeadObject is used for Object Lock fields not available in listing.
func headBundle(
	ctx context.Context,
	client *s3.Client,
	bucket, key string,
	_ s3types.Object,
) (BundleRecord, error) {
	head, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return BundleRecord{}, err
	}

	bt, orgID := parseKeyInfo(key)
	rec := BundleRecord{
		Key:          key,
		BundleType:   bt,
		OrgID:        orgID,
		SizeBytes:    aws.ToInt64(head.ContentLength),
		ETag:         strings.Trim(aws.ToString(head.ETag), `"`),
		LastModified: aws.ToTime(head.LastModified),
		LockMode:     string(head.ObjectLockMode),
		LegalHold:    string(head.ObjectLockLegalHoldStatus),
	}
	if head.ObjectLockRetainUntilDate != nil {
		t := *head.ObjectLockRetainUntilDate
		rec.RetainUntil = &t
	}
	return rec, nil
}

// manifestJSON is a minimal decode of bundle_manifest.json.
type manifestJSON struct {
	ExportTime time.Time `json:"export_time"`
	Tables     []string  `json:"tables"`
	OrgID      string    `json:"org_id"`
}

// fetchManifest downloads the zip and extracts bundle_manifest.json into rec.
// Only called when --read-manifest is set.
func fetchManifest(ctx context.Context, client *s3.Client, bucket string, rec *BundleRecord) error {
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(rec.Key),
	})
	if err != nil {
		return fmt.Errorf("GetObject: %w", err)
	}
	defer out.Body.Close()

	body, err := io.ReadAll(out.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("parse zip: %w", err)
	}

	for _, f := range zr.File {
		if path.Base(f.Name) != "bundle_manifest.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open manifest: %w", err)
		}
		defer rc.Close()

		var m manifestJSON
		if err := json.NewDecoder(rc).Decode(&m); err != nil {
			return fmt.Errorf("decode manifest: %w", err)
		}
		rec.ManifestOrgID = m.OrgID
		rec.ManifestTables = m.Tables
		t := m.ExportTime.UTC()
		rec.ManifestExportTime = &t
		return nil
	}
	return fmt.Errorf("bundle_manifest.json not found in zip")
}
