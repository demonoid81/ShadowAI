package proxy

import "sync"

// Registry holds all registered AI providers.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewRegistry creates a new empty provider registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
	}
}

// Register adds a provider to the registry.
func (r *Registry) Register(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.Name()] = p
}

// Get returns a provider by name.
func (r *Registry) Get(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	return p, ok
}

// List returns all registered provider names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}

// FindByModel returns all providers that list the given model in SupportedModels().
func (r *Registry) FindByModel(model string) []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []Provider
	for _, p := range r.providers {
		for _, m := range p.SupportedModels() {
			if m == model {
				result = append(result, p)
				break
			}
		}
	}
	return result
}

// ListProviders returns all registered providers.
func (r *Registry) ListProviders() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		result = append(result, p)
	}
	return result
}
