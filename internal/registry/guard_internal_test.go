package registry

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestDialerControlRechecksAddress(t *testing.T) {
	g := &guard{}
	for _, addr := range []string{"127.0.0.1:443", "[::1]:443", "10.0.0.1:443", "[::ffff:169.254.169.254]:443", "100.64.0.1:443", "93.184.216.10:8443"} {
		if err := g.control("tcp", addr, nil); !errors.Is(err, errBlocked) {
			t.Fatalf("%s: %v", addr, err)
		}
	}
	if err := g.control("tcp", "93.184.216.10:443", nil); err != nil {
		t.Fatalf("public: %v", err)
	}
	g.allowPrivate = true
	if err := g.control("tcp", "127.0.0.1:443", nil); err != nil {
		t.Fatalf("allow private: %v", err)
	}
}

// TestRealDialerRefusesLoopback dials a real local listener with the
// production dialer, bypassing dialContext, so only Control can refuse it.
func TestRealDialerRefusesLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := (&guard{}).dialer().DialContext(ctx, "tcp", ln.Addr().String())
	if err == nil {
		conn.Close()
		t.Fatal("dialled loopback")
	}
	if !errors.Is(err, errBlocked) {
		t.Fatalf("err %v, want errBlocked", err)
	}
	conn, err = (&guard{allowPrivate: true}).dialer().DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("allow private: %v", err)
	}
	conn.Close()
}

// TestNewServiceGuardsByDefault is the main.go construction: no test hooks,
// AllowPrivate false, the system resolver. A loopback literal host is
// refused before any connection.
func TestNewServiceGuardsByDefault(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- struct{}{}
			c.Close()
		}
	}()
	svc := NewService(Options{})
	_, _, err = svc.Client.Tags(context.Background(), Repo{Host: "127.0.0.1", Path: "app"})
	var re *Error
	if !errors.As(err, &re) || re.Code != CodeUnreachable {
		t.Fatalf("err %v", err)
	}
	if svc.HostAllowed("127.0.0.1:"+portOf(t, ln), true) {
		t.Fatal("a non-443 stored host is allowed")
	}
	select {
	case <-accepted:
		t.Fatal("connected")
	case <-time.After(50 * time.Millisecond):
	}
	if cap(svc.sem) != maxConcurrent {
		t.Fatalf("concurrency %d", cap(svc.sem))
	}
}

func portOf(t *testing.T, ln net.Listener) string {
	t.Helper()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}
