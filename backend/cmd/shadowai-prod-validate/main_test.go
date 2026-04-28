package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type fakeRunner struct {
	errByName map[string]error
	calls     []string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if err := f.errByName[name]; err != nil {
		return []byte("simulated failure"), err
	}
	return []byte("ok"), nil
}

func TestRun_NoChecks_ConfigError(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runWithDeps([]string{}, &out, &errOut, &fakeRunner{}, http.DefaultClient)
	if code != exitConfig {
		t.Fatalf("exit code = %d, want %d", code, exitConfig)
	}
	if !strings.Contains(errOut.String(), "at least one validation check") {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

func TestRun_AllConfiguredChecksPass_JSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/health" && r.URL.Path != "/api/ready" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	runner := &fakeRunner{}
	var out, errOut bytes.Buffer
	code := runWithDeps([]string{
		"--chart", "../../deploy/helm/shadowai",
		"--values", "../../deploy/helm/shadowai/values-prod.yaml",
		"--base-url", srv.URL,
		"--evidence-bundle", "/tmp/evidence.zip",
		"--bucket", "shadowai-evidence",
		"--require-object-lock",
		"--format", "json",
	}, &out, &errOut, runner, srv.Client())
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitOK, errOut.String())
	}
	if !strings.Contains(out.String(), `"overall": "pass"`) {
		t.Fatalf("json output does not report pass: %s", out.String())
	}
	for _, want := range []string{"helm template", "audit-verify --bundle", "audit-evidence-report --bucket"} {
		if !containsCall(runner.calls, want) {
			t.Fatalf("runner calls %v do not contain %q", runner.calls, want)
		}
	}
}

func TestRun_CommandFailure_ExitFailure(t *testing.T) {
	runner := &fakeRunner{errByName: map[string]error{"audit-verify": errors.New("bad bundle")}}
	var out, errOut bytes.Buffer
	code := runWithDeps([]string{
		"--evidence-bundle", "/tmp/evidence.zip",
		"--format", "json",
	}, &out, &errOut, runner, http.DefaultClient)
	if code != exitFailure {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitFailure, errOut.String())
	}
	if !strings.Contains(out.String(), `"overall": "fail"`) {
		t.Fatalf("json output does not report fail: %s", out.String())
	}
}

func TestRun_HTTPReadyNon200_ExitFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	code := runWithDeps([]string{
		"--base-url", srv.URL,
		"--format", "json",
	}, &out, &errOut, &fakeRunner{}, srv.Client())
	if code != exitFailure {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitFailure, errOut.String())
	}
	if !strings.Contains(out.String(), `"id": "http_ready"`) {
		t.Fatalf("json output missing ready check: %s", out.String())
	}
}

func TestRun_OutputFile_WritesReport(t *testing.T) {
	dir := t.TempDir()
	output := dir + "/report.json"
	var out, errOut bytes.Buffer
	code := runWithDeps([]string{
		"--evidence-bundle", "/tmp/evidence.zip",
		"--format", "json",
		"--output", output,
	}, &out, &errOut, &fakeRunner{}, http.DefaultClient)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitOK, errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout should be empty when --output is set, got %q", out.String())
	}
	b, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(b), `"overall": "pass"`) {
		t.Fatalf("output file does not contain report: %s", string(b))
	}
}

func TestRun_InvalidFormat_ConfigError(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runWithDeps([]string{
		"--evidence-bundle", "/tmp/evidence.zip",
		"--format", "xml",
	}, &out, &errOut, &fakeRunner{}, http.DefaultClient)
	if code != exitConfig {
		t.Fatalf("exit code = %d, want %d", code, exitConfig)
	}
}

func containsCall(calls []string, needle string) bool {
	for _, call := range calls {
		if strings.Contains(call, needle) {
			return true
		}
	}
	return false
}
