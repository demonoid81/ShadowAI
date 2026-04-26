// cmd/evidence-upload — PR-O4.2: Upload an evidence bundle to S3-compatible storage.
//
// Usage:
//
//	evidence-upload \
//	  --file /tmp/bundle.zip \
//	  --bucket shadowai-compliance \
//	  --key shadowai/evidence/2026/04/26/global-20260426-020000.zip \
//	  [--region us-east-1] \
//	  [--endpoint http://minio:9000] \
//	  [--force-path-style]
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
//	1 — upload failed (network, auth, S3 error)
//	2 — configuration error (missing flags, bad file path)
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
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

	fmt.Fprintf(stdout, "[evidence-upload] uploading %s → s3://%s/%s (%d bytes)\n",
		*file, *bucket, *key, stat.Size())

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
	// sse=none: omit the SSE header — required for MinIO and some custom S3 targets
	// that reject or ignore AES256 depending on server configuration.

	_, err = client.PutObject(ctx, putInput)
	if err != nil {
		return uploadErr("PutObject s3://%s/%s: %v", *bucket, *key, err)
	}

	fmt.Fprintf(stdout, "[evidence-upload] upload complete: s3://%s/%s\n", *bucket, *key)
	return exitOK
}
