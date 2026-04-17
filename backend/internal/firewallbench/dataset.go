package firewallbench

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Example — одна запись в jsonl-датасете.
//
// label: "positive" — инспектор ДОЛЖЕН задетектить (угроза);
//        "negative" — инспектор НЕ должен задетектить (чистый запрос).
// source — атрибуция (для LICENSES.md).
// license — идентификатор лицензии (MIT, Apache-2.0, CC0, custom).
type Example struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Text    string `json:"text"`
	Source  string `json:"source,omitempty"`
	License string `json:"license,omitempty"`
}

// LoadDataset читает jsonl-файл. Пустые строки игнорируются,
// невалидные — ошибка с указанием номера строки (для debug'а при
// правке dataset'ов вручную).
func LoadDataset(path string) ([]Example, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var examples []Example
	scanner := bufio.NewScanner(f)
	// Увеличенный буфер для длинных примеров (jailbreak-промты бывают
	// многострочными, хотя в jsonl они однострочные).
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var ex Example
		if err := json.Unmarshal([]byte(line), &ex); err != nil {
			return nil, fmt.Errorf("%s line %d: invalid json: %w", path, lineNo, err)
		}

		if err := validateExample(&ex); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, lineNo, err)
		}
		examples = append(examples, ex)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	return examples, nil
}

func validateExample(ex *Example) error {
	if ex.ID == "" {
		return fmt.Errorf("missing id")
	}
	if ex.Text == "" {
		return fmt.Errorf("missing text")
	}
	switch ex.Label {
	case "positive", "negative":
		return nil
	default:
		return fmt.Errorf("invalid label %q (want positive|negative)", ex.Label)
	}
}
