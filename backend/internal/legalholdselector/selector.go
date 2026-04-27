package legalholdselector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	maxDepth      = 3
	maxPredicates = 20
	maxInList     = 100
)

var ErrInvalidSelector = errors.New("legalhold selector: invalid selector")

type CompileOptions struct {
	ArgOffset int
}

type Compiled struct {
	NormalizedJSON []byte
	Hash           string
	Explanation    string
	SQL            string
	Args           []any
}

type node struct {
	Version int     `json:"v,omitempty"`
	All     []*node `json:"all,omitempty"`
	Any     []*node `json:"any,omitempty"`
	Field   string  `json:"field,omitempty"`
	Op      string  `json:"op,omitempty"`
	Value   any     `json:"value,omitempty"`
	sql     string  `json:"-"`
	args    []any   `json:"-"`
	explain string  `json:"-"`
	sortKey string  `json:"-"`
}

type parseState struct {
	predicates int
}

type fieldSpec struct {
	column string
	ops    map[string]bool
	kind   string
}

var fields = map[string]fieldSpec{
	"id":            {column: "id", ops: map[string]bool{"eq": true, "in": true}, kind: "string"},
	"created_at":    {column: "created_at", ops: map[string]bool{"between": true, "gte": true, "lte": true}, kind: "time"},
	"provider":      {column: "provider", ops: map[string]bool{"eq": true, "in": true}, kind: "string"},
	"model":         {column: "model", ops: map[string]bool{"eq": true, "in": true}, kind: "string"},
	"endpoint":      {column: "endpoint", ops: map[string]bool{"eq": true, "in": true}, kind: "string"},
	"policy_action": {column: "policy_action", ops: map[string]bool{"eq": true, "in": true}, kind: "string"},
	"outcome":       {column: "outcome", ops: map[string]bool{"eq": true, "in": true, "is_empty": true}, kind: "string"},
	"pii_detected":  {column: "pii_detected", ops: map[string]bool{"eq": true}, kind: "bool"},
}

func IsInvalid(err error) bool {
	return errors.Is(err, ErrInvalidSelector)
}

func Compile(raw json.RawMessage, opts CompileOptions) (Compiled, error) {
	if opts.ArgOffset <= 0 {
		opts.ArgOffset = 1
	}
	root, err := parse(raw)
	if err != nil {
		return Compiled{}, err
	}
	nextArg := opts.ArgOffset
	if err := compileNode(root, &nextArg); err != nil {
		return Compiled{}, err
	}
	normalized, err := json.Marshal(root)
	if err != nil {
		return Compiled{}, fmt.Errorf("marshal normalized selector: %w", err)
	}
	sum := sha256.Sum256(normalized)
	return Compiled{
		NormalizedJSON: normalized,
		Hash:           hex.EncodeToString(sum[:]),
		Explanation:    root.explain,
		SQL:            root.sql,
		Args:           root.args,
	}, nil
}

func invalid(msg string) error {
	return fmt.Errorf("%s: %w", msg, ErrInvalidSelector)
}
