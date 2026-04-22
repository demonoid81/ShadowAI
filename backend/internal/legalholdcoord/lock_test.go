//go:build enterprise

package legalholdcoord

import "testing"

// TestAdvisoryLockConstants — regression guard: namespace/resource
// литералы не меняются случайно. Смена значений в prod сломает
// совместимость между apply_hold и purge в running-процессе.
func TestAdvisoryLockConstants(t *testing.T) {
	if AdvisoryLockNamespace != 4201 {
		t.Errorf("AdvisoryLockNamespace = %d, want 4201", AdvisoryLockNamespace)
	}
	if HoldPurgeResource != 1 {
		t.Errorf("HoldPurgeResource = %d, want 1", HoldPurgeResource)
	}
}

// TestAcquireHoldPurgeLock_NilTx_ReturnsError — defence.
func TestAcquireHoldPurgeLock_NilTx_ReturnsError(t *testing.T) {
	err := AcquireHoldPurgeLock(nil, nil)
	if err == nil {
		t.Error("nil tx: err=nil, want error")
	}
}
