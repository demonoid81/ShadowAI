package pii

import "regexp"

type PatternDef struct {
	Name    string
	Pattern *regexp.Regexp
}

var Patterns = []PatternDef{
	{Name: "email", Pattern: regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)},
	{Name: "phone", Pattern: regexp.MustCompile(`(\+?[1-9]\d{0,2}[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}`)},
	{Name: "credit_card", Pattern: regexp.MustCompile(`\b(?:\d{4}[\s\-]?){3}\d{4}\b`)},
	{Name: "ssn", Pattern: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	{Name: "ip_address", Pattern: regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)},
}
