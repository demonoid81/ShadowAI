// cmd/evidence-upload — PR-O4.2/O4.3: Upload an evidence bundle to S3-compatible storage.
//
// Usage:
//
//	evidence-upload \
//	  --file /tmp/bundle.zip \
//	  --bucket shadowai-compliance \
//	  --key shadowai/evidence/2026/04/26/global-20260426-020000.zip \
//	  [--region us-east-1] \
//	  [--endpoint http://minio:9000] \
//	  [--force-path-style] \
//	  [--sse AES256|none] \
//	  [--object-lock-mode GOVERNANCE|COMPLIANCE --retain-until 90d] \
//	  [--legal-hold ON|OFF]
//
// Credentials via standard AWS env vars:
//
//	AWS_ACCESS_KEY_ID
//	AWS_SECRET_ACCESS_KEY
//	AWS_SESSION_TOKEN  (optional)
//
// Exit codes:
//
//	0 — upload successful
//	1 — upload failed (network, auth, S3 error; includes bucket Object Lock rejection)
//	2 — configuration error (missing flags, bad file path, invalid Object Lock args)
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	exitOK     = 0
	exitFail   = 1
	exitConfig = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("evidence-upload", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		file           = fs.String("file", "", "Path to the bundle file to upload (required)")
		bucket         = fs.String("bucket", "", "S3 bucket name (required)")
		key            = fs.String("key", "", "S3 object key / path (required)")
		region         = fs.String("region", "us-east-1", "AWS region")
		endpoint       = fs.String("endpoint", "", "Custom S3 endpoint URL (MinIO, GCS, etc.)")
		forcePathStyle = fs.Bool("force-path-style", false, "Use path-style addressing (required for many MinIO installs)")
		sse            = fs.String("sse", "AES256", `Server-Side Encryption: "AES256" (default, AWS S3) or "none" (MinIO/custom S3)`)
		timeout        = fs.Int("timeout", 300, "Upload timeout in seconds")
		// O4.3: S3 Object Lock
		objectLockMode = fs.String("object-lock-mode", "", `Object Lock retention mode: "GOVERNANCE" or "COMPLIANCE" (requires --retain-until)`)
		retainUntil    = fs.String("retain-until", "", `Object Lock retention date: RFC3339 (2026-07-25T00:00:00Z) or duration (90d, 8760h)`)
		legalHold      = fs.String("legal-hold", "", `Object Lock legal hold: "ON" or "OFF" (optional, independent of mode/retain-until)`)
	)
	if err := fs.Parse(args); err != nil {
		return exitConfig
	}

	cfgErr := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "config error: "+format+"\n", a...)
		return exitConfig
	}
	uploadErr := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "upload error: "+format+"\n", a...)
		return exitFail
	}

	if *file == "" {
		return cfgErr("--file is required")
	}
	if *bucket == "" {
		return cfgErr("--bucket is required")
	}
	if *key == "" {
		return cfgErr("--key is required")
	}
	switch *sse {
	case "AES256", "none":
	default:
		return cfgErr("--sse must be AES256 or none, got %q", *sse)
	}

	// O4.3: Object Lock flag validation.
	// mode and retain-until must be set together; partial config fails hard.
	if (*objectLockMode == "") != (*retainUntil == "") {
		if *objectLockMode == "" {
			return cfgErr("--object-lock-mode is required when --retain-until is set")
		}
		return cfgErr("--retain-until is required when --object-lock-mode is set")
	}
	var lockModeVal types.ObjectLockMode
	if *objectLockMode != "" {
		switch *objectLockMode {
		case "GOVERNANCE":
			lockModeVal = types.ObjectLockModeGovernance
		case "COMPLIANCE":
			lockModeVal = types.ObjectLockModeCompliance
		default:
			return cfgErr("--object-lock-mode must be GOVERNANCE or COMPLIANCE, got %q", *objectLockMode)
		}
	}
	var retainUntilTime time.Time
	if *retainUntil != "" {
		var err error
		retainUntilTime, err = parseRetainUntil(*retainUntil)
		if err != nil {
			return cfgErr("%v", err)
		}
		if !retainUntilTime.After(time.Now()) {
			return cfgErr("--retain-until must be in the future, got %s", retainUntilTime.Format(time.RFC3339))
		}
	}
	var legalHoldVal types.ObjectLockLegalHoldStatus
	if *legalHold != "" {
		switch *legalHold {
		case "ON":
			legalHoldVal = types.ObjectLockLegalHoldStatusOn
		case "OFF":
			legalHoldVal = types.ObjectLockLegalHoldStatusOff
		default:
			return cfgErr("--legal-hold must be ON or OFF, got %q", *legalHold)
		}
	}

	f, err := os.Open(*file)
	if err != nil {
		return cfgErr("open file %s: %v", *file, err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return cfgErr("stat file %s: %v", *file, err)
	}

	// Build SDK config.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
	defer cancel()

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(*region),
	}

	// Explicit credential override when env vars set (standard AWS chain used otherwise).
	if accessKey := os.Getenv("AWS_ACCESS_KEY_ID"); accessKey != "" {
		secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
		sessionToken := os.Getenv("AWS_SESSION_TOKEN")
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken),
		))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return cfgErr("load AWS config: %v", err)
	}

	// Build S3 client.
	s3Opts := []func(*s3.Options){}
	if *endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(*endpoint)
		})
	}
	if *forcePathStyle {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}
	client := s3.NewFromConfig(cfg, s3Opts...)

	lockSuffix := ""
	if *objectLockMode != "" {
		lockSuffix = fmt.Sprintf(" [object-lock=%s until=%s]", *objectLockMode, retainUntilTime.Format("2006-01-02"))
	}
	fmt.Fprintf(stdout, "[evidence-upload] uploading %s → s3://%s/%s (%d bytes)%s\n",
		*file, *bucket, *key, stat.Size(), lockSuffix)

	putInput := &s3.PutObjectInput{
		Bucket:        aws.String(*bucket),
		Key:           aws.String(*key),
		Body:          f,
		ContentLength: aws.Int64(stat.Size()),
		ContentType:   aws.String("application/zip"),
		Metadata: map[string]string{
			"shadowai-component": "evidence-bundle",
			"upload-timestamp":   time.Now().UTC().Format(time.RFC3339),
		},
	}
	if *sse == "AES256" {
		putInput.ServerSideEncryption = types.ServerSideEncryptionAes256
	}
	// sse=none: omit the SSE header — required for MinIO and some custom S3 targets.

	// O4.3: Object Lock headers. If mode+retain-until are set, apply retention.
	// If the bucket does not have Object Lock enabled, AWS/MinIO returns an error,
	// which propagates as exitFail — intentionally failing hard rather than degrading
	// to a mutable upload.
	if *objectLockMode != "" {
		putInput.ObjectLockMode = lockModeVal
		putInput.ObjectLockRetainUntilDate = aws.Time(retainUntilTime)
	}
	if *legalHold != "" {
		putInput.ObjectLockLegalHoldStatus = legalHoldVal
	}

	_, err = client.PutObject(ctx, putInput)
	if err != nil {
		return uploadErr("PutObject s3://%s/%s: %v", *bucket, *key, err)
	}

	fmt.Fprintf(stdout, "[evidence-upload] upload complete: s3://%s/%s\n", *bucket, *key)
	return exitOK
}

// parseRetainUntil parses --retain-until value.
//
// Accepts:
//   - RFC3339 timestamp: "2026-07-25T02:00:00Z"
//   - Days suffix:       "90d"  → now + 90 days
//   - Go duration:       "8760h" → now + 8760 hours
func parseRetainUntil(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if body, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(body)
		if err == nil && n > 0 {
			return time.Now().UTC().Add(time.Duration(n) * 24 * time.Hour), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return time.Now().UTC().Add(d), nil
	}
	return time.Time{}, fmt.Errorf("invalid --retain-until %q: use RFC3339 (e.g. 2026-07-25T02:00:00Z) or duration (e.g. 90d, 8760h)", s)
}
