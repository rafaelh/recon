package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// TCPResult is the outcome of a TCP connect. No connection is ever returned.
type TCPResult interface{ tcpResult() }

// Open means the handshake completed; Banner is whatever the service sent unprompted.
type Open struct{ Banner []byte }

// Closed means the port actively refused the connection.
type Closed struct{}

// Filtered means there was no answer (timeout or unreachable).
type Filtered struct{}

// Refused means policy refused the request; nothing was sent. It is a
// completed check, not a failure.
type Refused struct{ Reason string }

func (Open) tcpResult()     {}
func (Closed) tcpResult()   {}
func (Filtered) tcpResult() {}
func (Refused) tcpResult()  {}

// TargetTCP completes TCP handshakes to target-owned addresses and reads the banner.
type TargetTCP interface {
	Connect(ctx context.Context, addr netip.Addr, port int) (TCPResult, error)
}

type targetTCP struct{ e *Egress }

func (t *targetTCP) Connect(ctx context.Context, addr netip.Addr, port int) (TCPResult, error) {
	p := t.e.policy()
	if r, ok := p.targetRefusal(); ok {
		return r, nil
	}
	if !p.portAllowed(port, false) {
		return Refused{"port " + strconv.Itoa(port) + " not in the configured list"}, nil
	}
	addr = addr.Unmap()
	if ok, why, excluded := p.Scope.PortEligible(addr, p.isShared(addr), !p.ownerUnknown(addr)); !ok {
		if excluded {
			p.reportExcluded(addr.String(), why)
		}
		return Refused{why}, nil
	}
	if err := t.e.hostLimiter(addr).Wait(ctx); err != nil {
		return nil, err
	}
	return t.e.dialAndRead(ctx, addr, port)
}

func (e *Egress) dialAddr(addr netip.Addr, port int) string {
	hp := net.JoinHostPort(addr.String(), strconv.Itoa(port))
	if m, ok := e.opts.DialMap[hp]; ok {
		return m
	}
	return hp
}

func (e *Egress) dialAndRead(ctx context.Context, addr netip.Addr, port int) (TCPResult, error) {
	d := net.Dialer{Timeout: e.opts.ConnectTimeout}
	conn, err := d.DialContext(ctx, "tcp", e.dialAddr(addr, port))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		switch {
		case errors.Is(err, syscall.ECONNREFUSED):
			return Closed{}, nil
		case localFailure(err):
			return nil, err
		}
		return Filtered{}, nil
	}
	defer conn.Close()
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(e.opts.BannerWait))
	n, _ := conn.Read(buf)
	return Open{Banner: append([]byte(nil), buf[:n]...)}, nil
}

// localFailure reports whether a dial error is this machine's fault (out of
// descriptors, buffers or ephemeral ports, or no network) rather than an answer
// from the target. It is a transient failure, never a result.
func localFailure(err error) bool {
	for _, e := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM,
		syscall.EADDRNOTAVAIL, syscall.EADDRINUSE, syscall.ENETDOWN} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
