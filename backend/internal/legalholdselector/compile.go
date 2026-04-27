package legalholdselector

import (
	"fmt"
	"strings"
	"time"
)

func compileNode(n *node, nextArg *int) error {
	switch {
	case len(n.All) > 0:
		return compileGroup(n, " AND ", "all", nextArg)
	case len(n.Any) > 0:
		return compileGroup(n, " OR ", "any", nextArg)
	default:
		return compilePredicate(n, nextArg)
	}
}

func compileGroup(n *node, sep, label string, nextArg *int) error {
	var sqls []string
	var explains []string
	for _, child := range groupChildren(n) {
		if err := compileNode(child, nextArg); err != nil {
			return err
		}
		sqls = append(sqls, "("+child.sql+")")
		n.args = append(n.args, child.args...)
		explains = append(explains, child.explain)
	}
	n.sql = strings.Join(sqls, sep)
	if label == "any" {
		n.explain = "any of (" + strings.Join(explains, "; ") + ")"
	} else {
		n.explain = strings.Join(explains, " and ")
	}
	return nil
}

func compilePredicate(n *node, nextArg *int) error {
	spec := fields[n.Field]
	col := spec.column
	switch n.Op {
	case "eq":
		n.sql = fmt.Sprintf("%s = $%d", col, *nextArg)
		n.args = []any{toArg(n.Value)}
		*nextArg++
		n.explain = fmt.Sprintf("%s = %s", n.Field, explainValue(n.Value))
	case "in":
		values := n.Value.([]string)
		placeholders := make([]string, 0, len(values))
		for _, v := range values {
			placeholders = append(placeholders, fmt.Sprintf("$%d", *nextArg))
			n.args = append(n.args, v)
			*nextArg++
		}
		n.sql = fmt.Sprintf("%s IN (%s)", col, strings.Join(placeholders, ", "))
		n.explain = fmt.Sprintf("%s in [%s]", n.Field, strings.Join(values, ","))
	case "between":
		values := n.Value.([]string)
		start, _ := time.Parse(time.RFC3339Nano, values[0])
		end, _ := time.Parse(time.RFC3339Nano, values[1])
		n.sql = fmt.Sprintf("%s >= $%d AND %s <= $%d", col, *nextArg, col, *nextArg+1)
		n.args = []any{start, end}
		*nextArg += 2
		n.explain = fmt.Sprintf("%s between %s and %s", n.Field, values[0], values[1])
	case "gte", "lte":
		value := n.Value.(string)
		ts, _ := time.Parse(time.RFC3339Nano, value)
		op := map[string]string{"gte": ">=", "lte": "<="}[n.Op]
		n.sql = fmt.Sprintf("%s %s $%d", col, op, *nextArg)
		n.args = []any{ts}
		*nextArg++
		n.explain = fmt.Sprintf("%s %s %s", n.Field, op, value)
	case "is_empty":
		n.sql = fmt.Sprintf("(%s IS NULL OR %s = '')", col, col)
		n.explain = n.Field + " is empty"
	default:
		return invalid("unsupported operator")
	}
	return nil
}

func groupChildren(n *node) []*node {
	if len(n.All) > 0 {
		return n.All
	}
	return n.Any
}
