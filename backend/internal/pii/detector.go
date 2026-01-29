package pii

type Finding struct {
	Type  string `json:"type"`
	Match string `json:"match"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

func Scan(text string) []Finding {
	var findings []Finding
	for _, p := range Patterns {
		matches := p.Pattern.FindAllStringIndex(text, -1)
		for _, m := range matches {
			findings = append(findings, Finding{
				Type:  p.Name,
				Match: text[m[0]:m[1]],
				Start: m[0],
				End:   m[1],
			})
		}
	}
	return findings
}

func DetectedTypes(findings []Finding) []string {
	seen := make(map[string]bool)
	var types []string
	for _, f := range findings {
		if !seen[f.Type] {
			seen[f.Type] = true
			types = append(types, f.Type)
		}
	}
	return types
}
