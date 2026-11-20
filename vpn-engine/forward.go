package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type flowPolicy interface {
	allow(protocol int, source netip.AddrPort, destination netip.AddrPort) bool
	protect(fd int) bool
}

type upstreamDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type tunnel struct {
	link      device.Device
	stack     *stack.Stack
	policy    flowPolicy
	dialer    upstreamDialer
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	stopping  bool
	active    sync.WaitGroup
	flowSlots chan struct{}
}

func openTunnel(fd, mtu int, policy flowPolicy) (*tunnel, error) {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, _ string, raw syscall.RawConn) error {
			var allowed bool
			if err := raw.Control(func(fd uintptr) { allowed = policy.protect(int(fd)) }); err != nil {
				return err
			}
			if !allowed {
				return os.ErrPermission
			}
			return nil
		},
	}
	return openTunnelWithDialer(fd, mtu, policy, dialer)
}

func openTunnelWithDialer(fd, mtu int, policy flowPolicy, dialer upstreamDialer) (*tunnel, error) {
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	link, err := fdbased.Open(strconv.Itoa(dup), uint32(mtu), 0)
	if err != nil {
		_ = unix.Close(dup)
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	t := &tunnel{link: link, policy: policy, dialer: dialer, ctx: ctx, cancel: cancel, flowSlots: make(chan struct{}, 1024)}
	t.stack, err = core.CreateStack(&core.Config{LinkEndpoint: link, TransportHandler: t})
	if err != nil {
		cancel()
		link.Close()
		return nil, err
	}
	return t, nil
}

func (t *tunnel) close() {
	t.mu.Lock()
	t.stopping = true
	t.cancel()
	t.mu.Unlock()
	t.stack.Close()
	t.stack.Wait()
	t.active.Wait()
	t.link.Close()
}

func (t *tunnel) HandleTCP(conn adapter.TCPConn) {
	t.handle(conn, conn.ID(), unix.IPPROTO_TCP)
}

func (t *tunnel) HandleUDP(conn adapter.UDPConn) {
	t.handle(conn, conn.ID(), unix.IPPROTO_UDP)
}

func (t *tunnel) handle(conn net.Conn, id *stack.TransportEndpointID, protocol int) {
	t.mu.Lock()
	if t.stopping {
		t.mu.Unlock()
		conn.Close()
		return
	}
	select {
	case t.flowSlots <- struct{}{}:
	default:
		t.mu.Unlock()
		conn.Close()
		return
	}
	t.active.Add(1)
	t.mu.Unlock()

	go func() {
		defer t.active.Done()
		defer func() { <-t.flowSlots }()
		defer conn.Close()

		source := netip.AddrPortFrom(address(id.RemoteAddress.AsSlice()), id.RemotePort)
		dest := netip.AddrPortFrom(address(id.LocalAddress.AsSlice()), id.LocalPort)
		if !source.IsValid() || !dest.IsValid() || !t.policy.allow(protocol, source, dest) {
			return
		}

		network := "tcp"
		if protocol == unix.IPPROTO_UDP {
			network = "udp"
		}
		remote, err := t.dialer.DialContext(t.ctx, network, dest.String())
		if err != nil {
			return
		}
		defer remote.Close()
		stop := context.AfterFunc(t.ctx, func() {
			conn.Close()
			remote.Close()
		})
		defer stop()
		if protocol == unix.IPPROTO_TCP {
			relayTCP(conn, remote)
		} else {
			relayUDP(conn, remote)
		}
	}()
}

func address(raw []byte) netip.Addr {
	addr, _ := netip.AddrFromSlice(raw)
	return addr.Unmap()
}

func relayTCP(first, second net.Conn) {
	done := make(chan struct{})
	go func() {
		copyTCP(first, second)
		close(done)
	}()
	copyTCP(second, first)
	<-done
}

func copyTCP(to, from net.Conn) {
	if _, err := io.Copy(to, from); err != nil {
		to.Close()
		from.Close()
		return
	}
	if writer, ok := to.(interface{ CloseWrite() error }); ok {
		_ = writer.CloseWrite()
	}
}

func relayUDP(first, second net.Conn) {
	const idle = 45 * time.Second
	done := make(chan struct{})
	pump := func(to, from net.Conn) {
		buf := make([]byte, 65535)
		for {
			_ = from.SetReadDeadline(time.Now().Add(idle))
			n, err := from.Read(buf)
			if err != nil {
				return
			}
			_ = to.SetReadDeadline(time.Now().Add(idle))
			_ = to.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := to.Write(buf[:n]); err != nil {
				return
			}
		}
	}
	go func() {
		pump(first, second)
		first.Close()
		second.Close()
		close(done)
	}()
	pump(second, first)
	first.Close()
	second.Close()
	<-done
}
