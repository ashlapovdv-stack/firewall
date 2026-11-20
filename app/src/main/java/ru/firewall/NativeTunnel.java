package ru.firewall;

final class NativeTunnel {
    interface Policy {
        boolean allowFlow(int protocol, String local, int localPort, String remote, int remotePort);
        boolean protectSocket(int fd);
    }

    static {
        System.loadLibrary("firewall_vpn");
    }

    private NativeTunnel() {}

    static native long open(int fd, int mtu, Policy policy);
    static native void close(long handle);
}
