package legalholdselector

import (
	"encoding/json"
	"sort"
	"strings"
)

func parse(raw json.RawMessage) (*node, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, invalid("selector required")
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, invalid("selector node must be object")
	}
	if err := requireRootVersion(root); err != nil {
		return nil, err
	}
	st := &parseState{}
	n, err := parseNode(raw, 1, st)
	if err != nil {
		return nil, err
	}
	if st.predicates == 0 {
		return nil, invalid("selector must contain at least one predicate")
	}
	return n, nil
}

func parseNode(raw json.RawMessage, depth int, st *parseState) (*node, error) {
	if depth > maxDepth {
		return nil, invalid("selector exceeds max depth")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, invalid("selector node must be object")
	}
	if len(obj) == 0 {
		return nil, invalid("selector node must not be empty")
	}
	if err := rejectUnknownKeys(obj); err != nil {
		return nil, err
	}
	if vraw, ok := obj["v"]; ok {
		var version int
		if err := json.Unmarshal(vraw, &version); err != nil || version != 1 {
			return nil, invalid("unsupported selector version")
		}
	}
	hasAll := obj["all"] != nil
	hasAny := obj["any"] != nil
	hasField := obj["field"] != nil
	if boolCount(hasAll, hasAny, hasField) != 1 {
		return nil, invalid("selector node must contain exactly one of all, any, field")
	}
	switch {
	case hasAll:
		return parseGroup(obj, "all", depth, st)
	case hasAny:
		return parseGroup(obj, "any", depth, st)
	default:
		return parsePredicate(obj, st)
	}
}

func parseGroup(obj map[string]json.RawMessage, key string, depth int, st *parseState) (*node, error) {
	if err := rejectKeysExcept(obj, "v", key); err != nil {
		return nil, err
	}
	var rawChildren []json.RawMessage
	if err := json.Unmarshal(obj[key], &rawChildren); err != nil {
		return nil, invalid(key + " must be an array")
	}
	if len(rawChildren) == 0 {
		return nil, invalid(key + " must not be empty")
	}
	children := make([]*node, 0, len(rawChildren))
	for _, rawChild := range rawChildren {
		child, err := parseNode(rawChild, depth+1, st)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	sort.Slice(children, func(i, j int) bool {
		return children[i].sortKey < children[j].sortKey
	})
	n := &node{Version: versionAtRoot(obj)}
	if key == "all" {
		n.All = children
	} else {
		n.Any = children
	}
	n.sortKey = key + ":" + joinSortKeys(children)
	return n, nil
}

func parsePredicate(obj map[string]json.RawMessage, st *parseState) (*node, error) {
	if err := rejectKeysExcept(obj, "v", "field", "op", "value"); err != nil {
		return nil, err
	}
	st.predicates++
	if st.predicates > maxPredicates {
		return nil, invalid("selector exceeds max predicates")
	}
	var field, op string
	if err := json.Unmarshal(obj["field"], &field); err != nil {
		return nil, invalid("field must be string")
	}
	if err := json.Unmarshal(obj["op"], &op); err != nil {
		return nil, invalid("op must be string")
	}
	field = strings.TrimSpace(field)
	op = strings.TrimSpace(op)
	if field == "org_id" || field == "user_id" {
		return nil, invalid("tenant and user boundary fields are implicit")
	}
	spec, ok := fields[field]
	if !ok {
		return nil, invalid("unsupported field")
	}
	if !spec.ops[op] {
		return nil, invalid("unsupported operator for field")
	}
	value, err := normalizeValue(field, op, spec, obj["value"])
	if err != nil {
		return nil, err
	}
	n := &node{Version: versionAtRoot(obj), Field: field, Op: op, Value: value}
	sortKeyBytes, _ := json.Marshal(n)
	n.sortKey = string(sortKeyBytes)
	return n, nil
}

func requireRootVersion(obj map[string]json.RawMessage) error {
	vraw := obj["v"]
	if vraw == nil {
		return invalid("selector version required")
	}
	var version int
	if err := json.Unmarshal(vraw, &version); err != nil || version != 1 {
		return invalid("unsupported selector version")
	}
	return nil
}

func rejectUnknownKeys(obj map[string]json.RawMessage) error {
	for key := range obj {
		switch key {
		case "v", "all", "any", "field", "op", "value":
		default:
			return invalid("unknown selector key")
		}
	}
	return nil
}

func rejectKeysExcept(obj map[string]json.RawMessage, allowed ...string) error {
	set := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		set[key] = true
	}
	for key := range obj {
		if !set[key] {
			return invalid("selector key not allowed on this node")
		}
	}
	return nil
}

func versionAtRoot(obj map[string]json.RawMessage) int {
	if obj["v"] == nil {
		return 0
	}
	return 1
}

func joinSortKeys(children []*node) string {
	keys := make([]string, 0, len(children))
	for _, child := range children {
		keys = append(keys, child.sortKey)
	}
	return strings.Join(keys, "|")
}

func boolCount(values ...bool) int {
	var n int
	for _, v := range values {
		if v {
			n++
		}
	}
	return n
}
