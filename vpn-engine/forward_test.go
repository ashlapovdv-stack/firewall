//go:build linux && !android

package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type observedFlow struct {
	protocol int
	from     netip.AddrPort
	to       netip.AddrPort
}

type testPolicy struct {
	allowed bool
	seen    chan observedFlow
}

func (p testPolicy) allow(protocol int, source, destination netip.AddrPort) bool {
	p.seen <- observedFlow{protocol, source, destination}
	return p.allowed
}

func (testPolicy) protect(int) bool { return true }

type pipeDialer struct{ calls chan string }

func (d pipeDialer) DialContext(_ context.Context, network, target string) (net.Conn, error) {
	d.calls <- network + "/" + target
	relay, server := net.Pipe()
	go func() {
		defer server.Close()
		message := make([]byte, 4)
		if _, err := io.ReadFull(server, message); err == nil {
			_, _ = server.Write(message)
		}
	}()
	return relay, nil
}

func clientStack(t *testing.T, fd int) *stack.Stack {
	t.Helper()
	device, err := fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	t.Cleanup(s.Destroy)
	if err := s.CreateNIC(1, device); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		protocol tcpip.NetworkProtocolNumber
		address  netip.Addr
		prefix   int
	}{
		{ipv4.ProtocolNumber, netip.MustParseAddr("198.18.0.2"), 24},
		{ipv6.ProtocolNumber, netip.MustParseAddr("fd00::2"), 64},
	} {
		address := tcpip.ProtocolAddress{Protocol: item.protocol, AddressWithPrefix: tcpip.AddressWithPrefix{
			Address: tcpip.AddrFromSlice(item.address.AsSlice()), PrefixLen: item.prefix,
		}}
		if err := s.AddProtocolAddress(1, address, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1}})
	return s
}

func TestTunnelRoutesOnlyAllowedFlows(t *testing.T) {
	for _, tc := range []struct {
		name        string
		destination netip.Addr
		source      netip.Addr
		network     tcpip.NetworkProtocolNumber
		protocol    int
		allowed     bool
	}{
		{"allow IPv4 TCP", netip.MustParseAddr("198.18.0.3"), netip.MustParseAddr("198.18.0.2"),
			ipv4.ProtocolNumber, unix.IPPROTO_TCP, true},
		{"allow IPv6 UDP", netip.MustParseAddr("fd00::3"), netip.MustParseAddr("fd00::2"),
			ipv6.ProtocolNumber, unix.IPPROTO_UDP, true},
		{"deny IPv4 UDP", netip.MustParseAddr("198.18.0.3"), netip.MustParseAddr("198.18.0.2"),
			ipv4.ProtocolNumber, unix.IPPROTO_UDP, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(pair[0]); _ = unix.Close(pair[1]) })
			client := clientStack(t, pair[0])
			policy := testPolicy{tc.allowed, make(chan observedFlow, 1)}
			dialer := pipeDialer{make(chan string, 1)}
			engine, err := openTunnelWithDialer(pair[1], 1500, policy, dialer)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(engine.close)
			remote := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(tc.destination.AsSlice()), Port: 9191}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var conn net.Conn
			if tc.protocol == unix.IPPROTO_TCP {
				conn, err = gonet.DialContextTCP(ctx, client, remote, tc.network)
			} else {
				conn, err = gonet.DialUDP(client, nil, &remote, tc.network)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if _, err := conn.Write([]byte("test")); err != nil {
				t.Fatal(err)
			}
			select {
			case observation := <-policy.seen:
				if observation.protocol != tc.protocol || observation.from.Addr() != tc.source ||
					observation.to != netip.AddrPortFrom(tc.destination, 9191) {
					t.Fatalf("unexpected flow: %+v", observation)
				}
			case <-ctx.Done():
				t.Fatal("flow never reached the firewall policy")
			}
			if !tc.allowed {
				select {
				case target := <-dialer.calls:
					t.Fatalf("denied flow opened an upstream socket: %s", target)
				case <-time.After(50 * time.Millisecond):
					return
				}
			}
			reply := make([]byte, 4)
			if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "test" {
				t.Fatalf("reply %q, error %v", reply, err)
			}
		})
	}
}
