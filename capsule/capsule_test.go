package capsule

import (
	"testing"
)

func TestCapsult(t *testing.T) {
	cap := NewCapsule()
	t.Log(cap.Hex())
}
