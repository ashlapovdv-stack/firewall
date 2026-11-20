package ru.firewall;

import android.content.Context;
import android.content.SharedPreferences;

import java.net.InetAddress;
import java.net.Inet4Address;

record FtpSettings(String ssid, ClientSubnet clients, int port, PortRange dataPorts,
                   int serverPort, PortRange serverDataPorts) {
    static final String PREFERENCES = "home_ftp";
    static final int DEFAULT_PORT = 2122;
    static final int DEFAULT_SERVER_PORT = 2121;
    static final String DEFAULT_DATA = "22000-22007";
    static final String DEFAULT_SERVER_DATA = "32768-60999";

    static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
    }

    static FtpSettings load(SharedPreferences preferences) {
        if (!preferences.getBoolean("enabled", false)) return null;
        try {
            return parse(preferences.getString("ssid", ""), preferences.getString("subnet", ""),
                    preferences.getString("port", ""), preferences.getString("data", ""),
                    preferences.getString("server_port", ""), preferences.getString("server_data", ""));
        } catch (IllegalArgumentException invalid) {
            return null;
        }
    }

    static FtpSettings parse(String ssid, String subnet, String port, String data,
                             String serverPort, String serverData) {
        if (ssid.isEmpty() || ssid.equals("<unknown ssid>")) throw new IllegalArgumentException();
        int listen = port(port);
        int server = port(serverPort);
        PortRange listenData = PortRange.parse(data);
        PortRange backendData = PortRange.parse(serverData);
        if (listen == server || listenData.contains(listen) || listenData.contains(server)
                || backendData.contains(listen) || backendData.contains(server)
                || listenData.overlaps(backendData) || listenData.last() - listenData.first() >= 32) {
            throw new IllegalArgumentException();
        }
        return new FtpSettings(ssid, ClientSubnet.parse(subnet), listen, listenData, server, backendData);
    }

    static int port(String text) {
        if (!text.trim().matches("[0-9]{1,5}")) throw new IllegalArgumentException();
        int value = Integer.parseInt(text.trim());
        if (value < 1024 || value > 65535) throw new IllegalArgumentException();
        return value;
    }

    record PortRange(int first, int last) {
        static PortRange parse(String text) {
            String[] endpoints = text.trim().split("-", -1);
            if (endpoints.length > 2) throw new IllegalArgumentException();
            int start = port(endpoints[0]);
            int end = endpoints.length == 2 ? port(endpoints[1]) : start;
            if (end < start) throw new IllegalArgumentException();
            return new PortRange(start, end);
        }

        boolean contains(int port) {
            return port >= first && port <= last;
        }

        boolean overlaps(PortRange other) {
            return first <= other.last && other.first <= last;
        }
    }

    record ClientSubnet(int network, int mask) {
        static ClientSubnet parse(String cidr) {
            String[] parts = cidr.trim().split("/", -1);
            if (parts.length != 2 || !parts[1].matches("[0-9]{1,2}")) throw new IllegalArgumentException();
            int bits = Integer.parseInt(parts[1]);
            if (bits < 1 || bits > 32) throw new IllegalArgumentException();
            String[] octets = parts[0].split("\\.", -1);
            if (octets.length != 4) throw new IllegalArgumentException();
            int address = 0;
            for (String octet : octets) {
                if (!octet.matches("[0-9]{1,3}")) throw new IllegalArgumentException();
                int value = Integer.parseInt(octet);
                if (value > 255) throw new IllegalArgumentException();
                address = (address << 8) | value;
            }
            int mask = -1 << (32 - bits);
            return new ClientSubnet(address & mask, mask);
        }

        boolean contains(InetAddress address) {
            if (!(address instanceof Inet4Address)) return false;
            int value = 0;
            for (byte octet : address.getAddress()) value = (value << 8) | (octet & 255);
            return (value & mask) == network;
        }
    }
}
