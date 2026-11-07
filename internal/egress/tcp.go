package egress

import (
	"context"
	"errors"
	"fmt"
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
	if ok, why, excluded := p.Scope.PortEligible(addr, p.owner); !ok {
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
		return classifyDial(err, addr, e.routeLookup())
	}
	defer conn.Close()
	buf := make([]byte, 1024)
	if err := conn.SetReadDeadline(time.Now().Add(e.opts.BannerWait)); err != nil {
		return Open{}, nil // the port is open; without a deadline the read could block forever
	}
	n, _ := conn.Read(buf)
	return Open{Banner: append([]byte(nil), buf[:n]...)}, nil
}

// classifyDial turns a failed dial into a result: a refusal is Closed, no
// answer is Filtered, and a failure of this machine is an error (transient),
// including a routing error that route, a lookup for the same address,
// reproduces (localRoute).
func classifyDial(err error, addr netip.Addr, route func(netip.Addr) error) (TCPResult, error) {
	err = localRoute(err, addr, route)
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return Closed{}, nil
	case localFailure(err):
		return nil, err
	}
	return Filtered{}, nil
}

// errLocalRoute marks a dial error that this machine's routing table produced.
var errLocalRoute = errors.New("no route on this machine")

// routeErrnos are the dial errors that this machine's routing table and a remote
// router can both produce: ENETUNREACH (no route, or ICMP net unreachable),
// EHOSTUNREACH (an unreachable route, or ICMP host unreachable) and EACCES (a
// prohibit route, or ICMP administratively prohibited).
var routeErrnos = []syscall.Errno{syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.EACCES}

// localRoute marks err with errLocalRoute when it is one of routeErrnos and
// route, a lookup for the same address, fails with the same errno: no packet
// left this machine, so it is a local failure. Otherwise a router answered,
// which is an answer from the network, and err is returned unchanged.
func localRoute(err error, addr netip.Addr, route func(netip.Addr) error) error {
	for _, e := range routeErrnos {
		if errors.Is(err, e) {
			if errors.Is(route(addr), e) {
				return fmt.Errorf("%w: %w", errLocalRoute, err)
			}
			return err
		}
	}
	return err
}

// routeLookup is Options.RouteLookup, by default udpRoute.
func (e *Egress) routeLookup() func(netip.Addr) error {
	if e.opts.RouteLookup != nil {
		return e.opts.RouteLookup
	}
	return udpRoute
}

// udpRoute asks the kernel for a route to addr by connecting a UDP socket,
// which sends no datagram: a local routing-table query, not contact with the target.
func udpRoute(addr netip.Addr) error {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, 9)))
	if err != nil {
		return err
	}
	return c.Close()
}

// localFailure reports whether a dial error is this machine's fault (out of
// descriptors, buffers or ephemeral ports, no network, a local firewall
// refusing with EPERM, or a routing error marked by localRoute) rather than an
// answer from the target. It is a transient failure, never a result.
func localFailure(err error) bool {
	for _, e := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM,
		syscall.EADDRNOTAVAIL, syscall.EADDRINUSE, syscall.ENETDOWN, syscall.EPERM, errLocalRoute} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
