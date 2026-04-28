package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun_ConfigErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  map[string]string
		want string
	}{
		{name: "missing database", args: nil, env: map[string]string{"BYOK_ENABLED": "true", "DATABASE_URL": ""}, want: "DATABASE_URL"},
		{name: "byok disabled", args: []string{"--database-url", "postgres://db"}, env: map[string]string{"BYOK_ENABLED": "false"}, want: "BYOK_ENABLED=true"},
		{name: "invalid limit", args: []string{"--database-url", "postgres://db", "--limit", "0"}, env: map[string]string{"BYOK_ENABLED": "true"}, want: "--limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			if code != exitCfg {
				t.Fatalf("run exit=%d, want %d stdout=%q stderr=%q", code, exitCfg, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("stderr %q does not contain %q", stderr.String(), tt.want)
			}
		})
	}
}
