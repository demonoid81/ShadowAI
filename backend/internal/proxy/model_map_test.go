package proxy

import (
	"context"
	"net/http"
	"testing"
)

// testProvider implements Provider for testing.
type testProvider struct {
	name            string
	defaultModel    string
	supportedModels []string
	streamFormat    StreamFormat
}

func (p *testProvider) Name() string                { return p.name }
func (p *testProvider) DefaultModel() string         { return p.defaultModel }
func (p *testProvider) SupportedModels() []string    { return p.supportedModels }
func (p *testProvider) StreamFormat() StreamFormat    { return p.streamFormat }
func (p *testProvider) BuildRequest(_ context.Context, _ []byte, _ string) (*http.Request, error) {
	return nil, nil
}
func (p *testProvider) ParseResponse(_ []byte) (int, int, int, float64, error) {
	return 0, 0, 0, 0, nil
}

func newTestRegistry(providers ...*testProvider) *Registry {
	r := NewRegistry()
	for _, p := range providers {
		r.Register(p)
	}
	return r
}

func TestModelMapperResolve_ExactMatch(t *testing.T) {
	reg := newTestRegistry(
		&testProvider{name: "openai", supportedModels: []string{"gpt-4o", "gpt-4o-mini"}},
		&testProvider{name: "anthropic", supportedModels: []string{"claude-3-5-sonnet-20241022"}},
	)
	mapper := NewModelMapper(reg)

	tests := []struct {
		model    string
		wantName string
		wantOK   bool
	}{
		{"gpt-4o", "openai", true},
		{"claude-3-5-sonnet-20241022", "anthropic", true},
		{"gpt-4o-mini", "openai", true},
		{"unknown-model-xyz", "", false},
		{"", "", false},
	}

	for _, tt := range tests {
		name, ok := mapper.Resolve(tt.model)
		if ok != tt.wantOK {
			t.Errorf("Resolve(%q): got ok=%v, want %v", tt.model, ok, tt.wantOK)
		}
		if name != tt.wantName {
			t.Errorf("Resolve(%q): got name=%q, want %q", tt.model, name, tt.wantName)
		}
	}
}

func TestModelMapperResolve_PrefixHeuristic(t *testing.T) {
	reg := newTestRegistry(
		&testProvider{name: "openai", supportedModels: []string{"gpt-4o"}},
		&testProvider{name: "anthropic", supportedModels: []string{"claude-3-5-sonnet-20241022"}},
		&testProvider{name: "gemini", supportedModels: []string{"gemini-pro"}},
		&testProvider{name: "groq", supportedModels: []string{"llama-3-70b"}},
	)
	mapper := NewModelMapper(reg)

	tests := []struct {
		model    string
		wantName string
		wantOK   bool
	}{
		{"gpt-4-turbo-2024", "openai", true},
		{"claude-4-opus", "anthropic", true},
		{"gemini-2.0-flash", "gemini", true},
		{"llama3.1-8b", "groq", true},
	}

	for _, tt := range tests {
		name, ok := mapper.Resolve(tt.model)
		if ok != tt.wantOK {
			t.Errorf("Resolve(%q): got ok=%v, want %v", tt.model, ok, tt.wantOK)
		}
		if name != tt.wantName {
			t.Errorf("Resolve(%q): got name=%q, want %q", tt.model, name, tt.wantName)
		}
	}
}
