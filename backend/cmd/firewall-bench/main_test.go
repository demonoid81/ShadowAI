package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testDataDir — путь к committed датасетам относительно package.
// Тесты в Go запускаются с cwd = package dir, так что путь стабилен.
func testDataDir(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "testdata", "firewall_bench")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("testdata не найдена по пути %s: %v", p, err)
	}
	return p
}

// TestRun_MissingBaseline_FailsHard — PR-5.1 core: если baseline файл
// не существует и --allow-missing-baseline НЕ передан, run() должен
// вернуть exit 1 (runtime error). Это фиксирует CI-gate: misconfigured
// baseline path не должен тихо пропустить регрессии.
func TestRun_MissingBaseline_FailsHard(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--all",
		"--data", testDataDir(t),
		"--baseline", "/tmp/does-not-exist-pr51-test.json",
	}, &stdout, &stderr)

	if code != 1 {
		t.Errorf("exit code = %d, want 1 (fail-hard на missing baseline)", code)
	}
	errStr := stderr.String()
	if !strings.Contains(errStr, "baseline") {
		t.Errorf("stderr должен упомянуть baseline, got: %q", errStr)
	}
}

// TestRun_MissingBaseline_WithAllowFlag — ad-hoc путь: с флагом
// --allow-missing-baseline поведение должно деградировать до
// "warning + продолжить регрессия не проверяется". Exit 0, если метрики
// валидны (запускаем на committed datasets, которые проходят).
func TestRun_MissingBaseline_WithAllowFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--all",
		"--data", testDataDir(t),
		"--baseline", "/tmp/does-not-exist-pr51-test.json",
		"--allow-missing-baseline",
	}, &stdout, &stderr)

	if code != 0 {
		t.Errorf("exit code = %d, want 0 (ad-hoc прогон без baseline)", code)
	}
	out := stdout.String() + stderr.String()
	if !strings.Contains(out, "warning") {
		t.Errorf("без baseline ожидался warning в выводе, got: %q", out)
	}
}

// TestRun_InvalidJSONBaseline_AlwaysFails — invalid JSON (не missing)
// должен завершать exit 1 ДАЖЕ с --allow-missing-baseline. Граница:
// missing = осознанный bootstrap, corrupt = broken control plane.
func TestRun_InvalidJSONBaseline_AlwaysFails(t *testing.T) {
	// Пишем битый JSON в temp dir.
	tmp := t.TempDir()
	bad := filepath.Join(tmp, "baseline.json")
	if err := os.WriteFile(bad, []byte(`{ this is not valid json`), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
	}{
		{"без флага", []string{
			"--all",
			"--data", testDataDir(t),
			"--baseline", bad,
		}},
		{"с --allow-missing-baseline (не должен помочь)", []string{
			"--all",
			"--data", testDataDir(t),
			"--baseline", bad,
			"--allow-missing-baseline",
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, &stdout, &stderr)
			if code != 1 {
				t.Errorf("exit = %d, want 1 (invalid JSON — corrupt control plane)", code)
			}
			if !strings.Contains(stderr.String(), "baseline") {
				t.Errorf("stderr должен упомянуть baseline, got: %q", stderr.String())
			}
		})
	}
}

// TestRun_ValidBaseline_Passes — smoke: нормальный прогон с committed
// baseline.json даёт exit 0.
func TestRun_ValidBaseline_Passes(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--all",
		"--data", testDataDir(t),
	}, &stdout, &stderr)

	if code != 0 {
		t.Errorf("exit = %d, want 0 (committed baseline должен проходить)\nstderr: %s",
			code, stderr.String())
	}
}

// TestRun_RegressionDetected_Exit2 — override min-recall до 0.9
// гарантированно triggерит регрессию на текущих метриках.
func TestRun_RegressionDetected_Exit2(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--all",
		"--data", testDataDir(t),
		"--min-recall", "0.9",
	}, &stdout, &stderr)

	if code != 2 {
		t.Errorf("exit = %d, want 2 (regression)\nstdout: %s\nstderr: %s",
			code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "REGRESSIONS") {
		t.Errorf("stdout должен содержать 'REGRESSIONS', got: %s", stdout.String())
	}
}

// TestRun_NoArgs_Usage — без --inspector и --all CLI должен сразу
// завершиться exit 1 с explanatory error (а не висеть или паниковать).
func TestRun_NoArgs_Usage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--data", testDataDir(t)}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit = %d, want 1 (missing --inspector/--all)", code)
	}
}
