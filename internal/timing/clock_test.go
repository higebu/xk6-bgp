package timing

import (
	"testing"
	"time"
)

func TestNowMonotonic(t *testing.T) {
	a := Now()
	time.Sleep(100 * time.Microsecond)
	b := Now()

	if d := b.Sub(a); d <= 0 {
		t.Fatalf("expected positive duration, got %v", d)
	}
	if d := b.SubMicros(a); d < 50 {
		t.Fatalf("expected SubMicros >= 50, got %d", d)
	}
	if b.WallNs() < a.WallNs() {
		t.Fatalf("wall regressed: a=%d b=%d", a.WallNs(), b.WallNs())
	}
}

func TestMonoNsAdvances(t *testing.T) {
	a := Now()
	b := Now()
	if b.MonoNs() < a.MonoNs() {
		t.Fatalf("mono regressed: a=%d b=%d", a.MonoNs(), b.MonoNs())
	}
}
