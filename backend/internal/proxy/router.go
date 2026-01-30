package proxy

import (
	"context"
	"fmt"
	"sort"
	"sync/atomic"
)

// RoutingStrategy defines how providers are ordered when no model is specified.
type RoutingStrategy string

const (
	StrategyCheapest   RoutingStrategy = "cheapest"
	StrategyFastest    RoutingStrategy = "fastest"
	StrategyRoundRobin RoutingStrategy = "round-robin"
)

// RouteResult is a candidate provider returned by the Router.
type RouteResult struct {
	Provider Provider
	Name     string
}

// Router selects and orders providers for a request.
type Router struct {
	registry      *Registry
	healthTracker *HealthTracker
	modelMapper   *ModelMapper
	strategy      RoutingStrategy
	fallbackOrder []string
	rrCounter     atomic.Uint64
}

// NewRouter creates a new Router.
func NewRouter(
	registry *Registry,
	healthTracker *HealthTracker,
	modelMapper *ModelMapper,
	strategy RoutingStrategy,
	fallbackOrder []string,
) *Router {
	return &Router{
		registry:      registry,
		healthTracker: healthTracker,
		modelMapper:   modelMapper,
		strategy:      strategy,
		fallbackOrder: fallbackOrder,
	}
}

// Route returns an ordered list of candidate providers for the given model.
// The first element is the primary choice; the rest are fallbacks.
func (rt *Router) Route(ctx context.Context, model string) ([]RouteResult, error) {
	// If model is specified, use model mapper to find the primary provider
	if model != "" {
		candidates := rt.registry.FindByModel(model)
		if len(candidates) > 0 {
			return rt.toRouteResults(candidates), nil
		}

		// Try model mapper (prefix heuristic)
		if name, ok := rt.modelMapper.Resolve(model); ok {
			if p, exists := rt.registry.Get(name); exists {
				results := []RouteResult{{Provider: p, Name: name}}
				// Add other providers as fallback
				for _, fp := range rt.registry.ListProviders() {
					if fp.Name() != name {
						results = append(results, RouteResult{Provider: fp, Name: fp.Name()})
					}
				}
				return results, nil
			}
		}
	}

	// No model or unrecognized model — use strategy
	providers := rt.registry.ListProviders()
	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers registered")
	}

	// If fallbackOrder is configured, use it as base ordering
	if len(rt.fallbackOrder) > 0 {
		return rt.orderByFallback(providers), nil
	}

	switch rt.strategy {
	case StrategyFastest:
		return rt.orderByLatency(ctx, providers), nil
	case StrategyRoundRobin:
		return rt.orderRoundRobin(providers), nil
	default: // cheapest
		return rt.orderByCost(providers), nil
	}
}

func (rt *Router) toRouteResults(providers []Provider) []RouteResult {
	results := make([]RouteResult, len(providers))
	for i, p := range providers {
		results[i] = RouteResult{Provider: p, Name: p.Name()}
	}
	return results
}

// costRank maps provider names to a relative cost rank (lower = cheaper).
var costRank = map[string]int{
	"ollama":     0,
	"groq":       1,
	"mistral":    2,
	"gemini":     3,
	"openrouter": 4,
	"openai":     5,
	"anthropic":  6,
}

func (rt *Router) orderByCost(providers []Provider) []RouteResult {
	sorted := make([]Provider, len(providers))
	copy(sorted, providers)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, _ := costRank[sorted[i].Name()]
		rj, _ := costRank[sorted[j].Name()]
		return ri < rj
	})
	return rt.toRouteResults(sorted)
}

func (rt *Router) orderByLatency(ctx context.Context, providers []Provider) []RouteResult {
	health := rt.healthTracker.GetAllHealth(ctx, providerNames(providers))
	sorted := make([]Provider, len(providers))
	copy(sorted, providers)
	sort.SliceStable(sorted, func(i, j int) bool {
		hi := health[sorted[i].Name()]
		hj := health[sorted[j].Name()]
		if hi.AvgLatencyMs == 0 && hj.AvgLatencyMs == 0 {
			return false
		}
		if hi.AvgLatencyMs == 0 {
			return false // no data → put at end
		}
		if hj.AvgLatencyMs == 0 {
			return true
		}
		return hi.AvgLatencyMs < hj.AvgLatencyMs
	})
	return rt.toRouteResults(sorted)
}

func (rt *Router) orderRoundRobin(providers []Provider) []RouteResult {
	// Sort providers by name for deterministic ordering
	sorted := make([]Provider, len(providers))
	copy(sorted, providers)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Name() < sorted[j].Name()
	})

	n := len(sorted)
	idx := int(rt.rrCounter.Add(1)-1) % n

	result := make([]RouteResult, n)
	for i := 0; i < n; i++ {
		p := sorted[(idx+i)%n]
		result[i] = RouteResult{Provider: p, Name: p.Name()}
	}
	return result
}

func (rt *Router) orderByFallback(providers []Provider) []RouteResult {
	byName := make(map[string]Provider, len(providers))
	for _, p := range providers {
		byName[p.Name()] = p
	}

	var results []RouteResult
	seen := make(map[string]bool)
	for _, name := range rt.fallbackOrder {
		if p, ok := byName[name]; ok && !seen[name] {
			results = append(results, RouteResult{Provider: p, Name: name})
			seen[name] = true
		}
	}
	// Append remaining providers not in fallback list
	for _, p := range providers {
		if !seen[p.Name()] {
			results = append(results, RouteResult{Provider: p, Name: p.Name()})
		}
	}
	return results
}

func providerNames(providers []Provider) []string {
	names := make([]string, len(providers))
	for i, p := range providers {
		names[i] = p.Name()
	}
	return names
}
