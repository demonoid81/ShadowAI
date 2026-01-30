package proxy

import "strings"

// ModelMapper resolves model names to provider names using the registry
// and prefix-based heuristics.
type ModelMapper struct {
	registry *Registry
}

// NewModelMapper creates a new ModelMapper backed by the given registry.
func NewModelMapper(registry *Registry) *ModelMapper {
	return &ModelMapper{registry: registry}
}

// prefixProviderMap maps model name prefixes to provider names.
var prefixProviderMap = []struct {
	prefix   string
	provider string
}{
	{"gpt-", "openai"},
	{"o1-", "openai"},
	{"o3-", "openai"},
	{"claude-", "anthropic"},
	{"gemini-", "gemini"},
	{"mistral-", "mistral"},
	{"llama", "groq"},
	{"mixtral", "groq"},
}

// Resolve determines the provider name for a given model.
// It first checks all registered providers' SupportedModels,
// then falls back to prefix-based heuristics.
func (m *ModelMapper) Resolve(model string) (providerName string, ok bool) {
	if model == "" {
		return "", false
	}

	// Exact match across registry
	for _, p := range m.registry.ListProviders() {
		for _, sm := range p.SupportedModels() {
			if sm == model {
				return p.Name(), true
			}
		}
	}

	// Prefix heuristic
	lower := strings.ToLower(model)
	for _, pm := range prefixProviderMap {
		if strings.HasPrefix(lower, pm.prefix) {
			// Verify provider is registered
			if _, exists := m.registry.Get(pm.provider); exists {
				return pm.provider, true
			}
		}
	}

	return "", false
}
