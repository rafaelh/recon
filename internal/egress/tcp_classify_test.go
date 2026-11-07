package egress_test

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"

	"github.com/rafaelh/recon/internal/egress"
)

// dialError is shaped like the error net.Dialer returns, so errors.Is has to
// unwrap OpError and SyscallError to reach the errno.
func dialError(e syscall.Errno) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", e)}
}

// Spec 4 D12 / B2: what a dial error means.
func TestClassifyDial(t *testing.T) {
	a := netip.MustParseAddr("203.0.113.5")
	noRoute := func(netip.Addr) error { return dialError(syscall.ENETUNREACH) }
	unreachableRoute := func(netip.Addr) error { return dialError(syscall.EHOSTUNREACH) }
	prohibitRoute := func(netip.Addr) error { return dialError(syscall.EACCES) }
	routed := func(netip.Addr) error { return nil }
	neverCalled := func(netip.Addr) error { t.Error("route lookup used for an error that does not need it"); return nil }

	for _, c := range []struct {
		name  string
		err   error
		route func(netip.Addr) error
		want  string // closed, filtered or error
	}{
		{"refused", dialError(syscall.ECONNREFUSED), neverCalled, "closed"},
		{"timeout", os.ErrDeadlineExceeded, neverCalled, "filtered"},
		{"a remote host unreachable", dialError(syscall.EHOSTUNREACH), routed, "filtered"},
		{"an unreachable route on this machine", dialError(syscall.EHOSTUNREACH), unreachableRoute, "error"},
		{"a remote administrative prohibition", dialError(syscall.EACCES), routed, "filtered"},
		{"a prohibit route on this machine", dialError(syscall.EACCES), prohibitRoute, "error"},
		{"local firewall (EPERM)", dialError(syscall.EPERM), neverCalled, "error"},
		{"out of descriptors", dialError(syscall.EMFILE), neverCalled, "error"},
		{"network down", dialError(syscall.ENETDOWN), neverCalled, "error"},
		{"no route on this machine", dialError(syscall.ENETUNREACH), noRoute, "error"},
		{"a remote router answered", dialError(syscall.ENETUNREACH), routed, "filtered"},
		{"route lookup fails otherwise", dialError(syscall.ENETUNREACH), prohibitRoute, "filtered"},
	} {
		res, err := egress.ClassifyDial(c.err, a, c.route)
		got := "error"
		if err == nil {
			switch res.(type) {
			case egress.Closed:
				got = "closed"
			case egress.Filtered:
				got = "filtered"
			default:
				got = "other result"
			}
		} else if !errors.Is(err, c.err) {
			t.Errorf("%s: the error must wrap the dial error, got %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// The route lookup is made to the address that was dialled.
func TestClassifyDialLooksUpTheSameAddress(t *testing.T) {
	a := netip.MustParseAddr("2001:db8::5")
	var got netip.Addr
	_, _ = egress.ClassifyDial(dialError(syscall.ENETUNREACH), a, func(x netip.Addr) error { got = x; return nil })
	if got != a {
		t.Errorf("route lookup for %v, want %v", got, a)
	}
}

// The default route lookup is a local routing-table query: it succeeds for loopback.
func TestUDPRouteLoopback(t *testing.T) {
	if err := egress.UDPRoute(netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Errorf("route to loopback: %v", err)
	}
}
