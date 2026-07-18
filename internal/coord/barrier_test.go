package coord

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBarrier_Releases(t *testing.T) {
	b, err := NewBarrier(5)
	if err != nil {
		t.Fatalf("NewBarrier: %v", err)
	}
	var wg sync.WaitGroup
	var released atomic.Int64
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Arrive()
			released.Add(1)
		}()
	}
	wg.Wait()
	if got := released.Load(); got != 5 {
		t.Fatalf("released=%d, want 5", got)
	}
}

func TestBarrier_BlocksUntilFull(t *testing.T) {
	b, err := NewBarrier(3)
	if err != nil {
		t.Fatalf("NewBarrier: %v", err)
	}
	var early atomic.Int64
	for range 2 {
		go func() {
			b.Arrive()
			early.Add(1)
		}()
	}
	time.Sleep(50 * time.Millisecond)
	if got := early.Load(); got != 0 {
		t.Fatalf("released %d before quorum, want 0", got)
	}
	b.Arrive() // trips the barrier
	// brief settle for the goroutines to advance past Arrive
	deadline := time.Now().Add(200 * time.Millisecond)
	for early.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := early.Load(); got != 2 {
		t.Fatalf("released=%d after quorum, want 2", got)
	}
}

func TestBarrier_InvalidTarget(t *testing.T) {
	if _, err := NewBarrier(0); err == nil {
		t.Fatal("NewBarrier(0) returned nil error")
	}
	if _, err := NewBarrier(-1); err == nil {
		t.Fatal("NewBarrier(-1) returned nil error")
	}
}

func TestRegistry_SameInstance(t *testing.T) {
	r := NewRegistry()
	b1, err := r.Barrier("rendezvous", 4)
	if err != nil {
		t.Fatalf("Barrier #1: %v", err)
	}
	b2, err := r.Barrier("rendezvous", 4)
	if err != nil {
		t.Fatalf("Barrier #2: %v", err)
	}
	if b1 != b2 {
		t.Fatalf("Registry returned different Barrier pointers for the same name")
	}
}

func TestBarrier_ArriveTimeout(t *testing.T) {
	b, err := NewBarrier(2)
	if err != nil {
		t.Fatalf("NewBarrier: %v", err)
	}
	start := time.Now()
	if _, err := b.ArriveTimeout(20 * time.Millisecond); err != ErrBarrierTimeout {
		t.Fatalf("err=%v, want ErrBarrierTimeout", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("timeout not honored: %s", time.Since(start))
	}
	// The timed-out arrival still counts: a single further Arrive
	// completes the rendezvous instead of wedging.
	done := make(chan int64, 1)
	go func() { done <- b.Arrive() }()
	select {
	case n := <-done:
		if n != 2 {
			t.Fatalf("second arrival index=%d, want 2", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("barrier did not release after timed-out arrival + one more Arrive")
	}
}
