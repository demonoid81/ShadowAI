//go:build enterprise

package main

import "github.com/shadowai/backend/perf"

func runGovernanceBenches(r *perf.Runner) []perf.BenchResult {
	return []perf.BenchResult{
		perf.GovernanceCacheHit(r),
		perf.GovernanceCacheMiss(r),
		perf.GovernanceEvaluate(r),
		perf.GovernanceEvaluateDeny(r),
	}
}

func runSIEMBenches(r *perf.Runner) []perf.BenchResult {
	return []perf.BenchResult{
		perf.SIEMEnqueueNormal(r),
		perf.SIEMEnqueueBackpressure(r),
	}
}
