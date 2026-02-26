package aperture

import (
	"testing"
)

func TestCircuitBreakerTripAndReset(t *testing.T) {
	cb := NewCircuitBreaker()

	if cb.IsTripped("port_scan") {
		t.Fatal("should not be tripped initially")
	}

	cb.Trip("port_scan")
	if !cb.IsTripped("port_scan") {
		t.Fatal("should be tripped after Trip()")
	}

	if cb.IsTripped("tls_check") {
		t.Fatal("other tools should not be affected")
	}

	cb.Reset("port_scan")
	if cb.IsTripped("port_scan") {
		t.Fatal("should not be tripped after Reset()")
	}
}
