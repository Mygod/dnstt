package main

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

type stubSession struct {
	openErr   error
	openCalls int32
}

func (s *stubSession) OpenStream() (*smux.Stream, error) {
	atomic.AddInt32(&s.openCalls, 1)
	return nil, s.openErr
}

func (s *stubSession) Close() error {
	return nil
}

func TestGetSessionSerializesCreate(t *testing.T) {
	sm := &sessionManager{}

	var createCalls int32
	started := make(chan struct{})
	release := make(chan struct{})
	var startOnce sync.Once

	sm.createSessionFn = func(closeExisting bool) error {
		if !closeExisting {
			t.Fatal("expected closeExisting true for getSession")
		}
		atomic.AddInt32(&createCalls, 1)
		startOnce.Do(func() { close(started) })
		<-release

		sm.mu.Lock()
		sm.sess = &stubSession{openErr: errors.New("no stream")}
		sm.conv = 1
		sm.mu.Unlock()
		return nil
	}

	const goroutines = 5
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := sm.getSession()
			errs <- err
		}()
	}

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for session creation")
	}
	close(release)

	wg.Wait()
	close(errs)

	if got := atomic.LoadInt32(&createCalls); got != 1 {
		t.Fatalf("expected 1 createSession call, got %d", got)
	}

	for err := range errs {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

func TestOpenStreamRecreatesOnGoAway(t *testing.T) {
	sm := &sessionManager{}
	sm.sess = &stubSession{openErr: smux.ErrGoAway}
	sm.conv = 1

	var createCalls int32
	sm.createSessionFn = func(closeExisting bool) error {
		if closeExisting {
			t.Fatal("expected closeExisting false for goaway")
		}
		atomic.AddInt32(&createCalls, 1)
		sm.mu.Lock()
		sm.sess = &stubSession{openErr: errors.New("still closed")}
		sm.conv = 2
		sm.mu.Unlock()
		return nil
	}

	_, _, _, err := sm.openStream()
	if err == nil {
		t.Fatal("expected error")
	}
	if got := atomic.LoadInt32(&createCalls); got != 1 {
		t.Fatalf("expected 1 createSession call, got %d", got)
	}
}

func TestOpenStreamRecreateSerializes(t *testing.T) {
	sm := &sessionManager{}
	sm.sess = &stubSession{openErr: io.ErrClosedPipe}
	sm.conv = 1

	var createCalls int32
	started := make(chan struct{})
	release := make(chan struct{})
	var startOnce sync.Once

	sm.createSessionFn = func(closeExisting bool) error {
		if !closeExisting {
			t.Fatal("expected closeExisting true for closed pipe")
		}
		atomic.AddInt32(&createCalls, 1)
		startOnce.Do(func() { close(started) })
		<-release

		sm.mu.Lock()
		sm.sess = &stubSession{openErr: errors.New("still closed")}
		sm.conv = 2
		sm.mu.Unlock()
		return nil
	}

	const goroutines = 5
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, err := sm.openStream()
			errs <- err
		}()
	}

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for session recreation")
	}
	close(release)

	wg.Wait()
	close(errs)

	if got := atomic.LoadInt32(&createCalls); got != 1 {
		t.Fatalf("expected 1 createSession call, got %d", got)
	}
	for err := range errs {
		if err == nil {
			t.Fatal("expected error")
		}
	}
}
