//go:build android

package main

/*
#include <stdint.h>
#include "bridge.h"
*/
import "C"

import (
	"net/netip"
	"runtime/cgo"
	"unsafe"
)

type androidPolicy struct {
	callback *C.struct_FirewallCallbacks
}

func (p androidPolicy) allow(protocol int, source, destination netip.AddrPort) bool {
	local := C.CString(source.Addr().String())
	remote := C.CString(destination.Addr().String())
	defer C.free(unsafe.Pointer(local))
	defer C.free(unsafe.Pointer(remote))
	return C.firewall_allow(p.callback, C.int(protocol), local, C.int(source.Port()), remote,
		C.int(destination.Port())) != 0
}

func (p androidPolicy) protect(fd int) bool {
	return C.firewall_protect(p.callback, C.int(fd)) != 0
}

//export firewall_start
func firewall_start(fd, mtu C.int, callback *C.struct_FirewallCallbacks) C.uintptr_t {
	t, err := openTunnel(int(fd), int(mtu), androidPolicy{callback: callback})
	if err != nil {
		return 0
	}
	return C.uintptr_t(cgo.NewHandle(t))
}

//export firewall_stop
func firewall_stop(raw C.uintptr_t) {
	handle := cgo.Handle(raw)
	t := handle.Value().(*tunnel)
	t.close()
	C.firewall_release(t.policy.(androidPolicy).callback)
	handle.Delete()
}

func main() {}
