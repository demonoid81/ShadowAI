package legalholdselector

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

func normalizeValue(field, op string, spec fieldSpec, raw json.RawMessage) (any, error) {
	if op == "is_empty" {
		if len(raw) != 0 && strings.TrimSpace(string(raw)) != "null" {
			return nil, invalid("is_empty does not accept value")
		}
		return nil, nil
	}
	if len(raw) == 0 {
		return nil, invalid("value required")
	}
	switch op {
	case "eq":
		switch spec.kind {
		case "bool":
			var v bool
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, invalid("value must be boolean")
			}
			return v, nil
		case "time":
			return parseTimeValue(raw)
		default:
			return parseStringValue(raw)
		}
	case "in":
		if spec.kind != "string" {
			return nil, invalid("in only supports string fields")
		}
		return parseStringList(raw)
	case "between":
		if field != "created_at" {
			return nil, invalid("between only supports created_at")
		}
		return parseTimePair(raw)
	case "gte", "lte":
		if field != "created_at" {
			return nil, invalid(op + " only supports created_at")
		}
		return parseTimeValue(raw)
	default:
		return nil, invalid("unsupported operator")
	}
}

func parseStringValue(raw json.RawMessage) (string, error) {
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", invalid("value must be string")
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", invalid("value must not be empty")
	}
	return v, nil
}

func parseStringList(raw json.RawMessage) ([]string, error) {
	var in []string
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, invalid("value must be string array")
	}
	if len(in) == 0 {
		return nil, invalid("in list must not be empty")
	}
	if len(in) > maxInList {
		return nil, invalid("in list too large")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			return nil, invalid("in list contains empty value")
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out, nil
}

func parseTimeValue(raw json.RawMessage) (string, error) {
	s, err := parseStringValue(raw)
	if err != nil {
		return "", err
	}
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return "", invalid("timestamp must be RFC3339")
	}
	return ts.UTC().Format(time.RFC3339Nano), nil
}

func parseTimePair(raw json.RawMessage) ([]string, error) {
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil || len(values) != 2 {
		return nil, invalid("between value must contain two timestamps")
	}
	start, err := parseTimeValue(mustMarshal(values[0]))
	if err != nil {
		return nil, err
	}
	end, err := parseTimeValue(mustMarshal(values[1]))
	if err != nil {
		return nil, err
	}
	startT, _ := time.Parse(time.RFC3339Nano, start)
	endT, _ := time.Parse(time.RFC3339Nano, end)
	if startT.After(endT) {
		return nil, invalid("between start must be <= end")
	}
	return []string{start, end}, nil
}

func toArg(v any) any {
	if s, ok := v.(string); ok {
		if ts, err := time.Parse(time.RFC3339Nano, s); err == nil && strings.Contains(s, "T") {
			return ts
		}
	}
	return v
}

func explainValue(v any) string {
	switch typed := v.(type) {
	case string:
		return typed
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprint(v)
	}
}

func mustMarshal(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
