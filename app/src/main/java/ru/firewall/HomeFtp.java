package ru.firewall;

import android.Manifest;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.location.LocationManager;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;

final class HomeFtp {
    private record WifiIdentity(Network network, String ssid, boolean lost) {}
    private record Binding(FtpSettings settings, Network network, InetAddress address) {}

    private final Context context;
    private final ConnectivityManager connectivity;
    private final SharedPreferences preferences;
    private volatile WifiIdentity wifiIdentity;
    private Binding current;
    private FtpProxy proxy;

    HomeFtp(Context context) {
        this.context = context;
        connectivity = context.getSystemService(ConnectivityManager.class);
        preferences = FtpSettings.preferences(context);
    }

    void capabilities(Network network, NetworkCapabilities capabilities) {
        String ssid = null;
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                && capabilities.getTransportInfo() instanceof WifiInfo info) {
            ssid = canonicalSsid(info.getSSID());
        }
        wifiIdentity = new WifiIdentity(network, ssid, false);
    }

    void lost(Network network) {
        WifiIdentity last = wifiIdentity;
        if ((last != null && network.equals(last.network()))
                || (current != null && network.equals(current.network()))) {
            wifiIdentity = new WifiIdentity(network, null, true);
        }
    }

    boolean configured() {
        return preferences.getBoolean("enabled", false);
    }

    void refresh() {
        FtpSettings settings = FtpSettings.load(preferences);
        if (settings == null) {
            disable(configured() ? R.string.ftp_invalid : R.string.ftp_off);
            return;
        }
        if (!canReadSsid(context)) {
            disable(R.string.ftp_location_needed);
            return;
        }
        Network network = connectivity.getActiveNetwork();
        if (!isHome(settings, network)) {
            disable(R.string.ftp_waiting_home);
            return;
        }
        LinkProperties link = connectivity.getLinkProperties(network);
        InetAddress address = null;
        if (link != null) {
            for (LinkAddress candidate : link.getLinkAddresses()) {
                if (candidate.getAddress() instanceof Inet4Address) {
                    address = candidate.getAddress();
                    break;
                }
            }
        }
        if (address == null) {
            disable(R.string.ftp_waiting_address);
            return;
        }
        Binding next = new Binding(settings, network, address);
        if (next.equals(current) && proxy != null) return;
        closeProxy();
        try {
            proxy = new FtpProxy(settings, address, () -> isHome(settings, network));
            current = next;
            FirewallStatus.postFtp(context.getString(R.string.ftp_active, address.getHostAddress(), settings.port()));
        } catch (IOException | RuntimeException unavailable) {
            FirewallStatus.postFtp(context.getString(R.string.ftp_bind_failed));
        }
    }

    private boolean isHome(FtpSettings settings, Network network) {
        if (network == null || !canReadSsid(context)
                || !network.equals(connectivity.getActiveNetwork())
                || !settings.equals(FtpSettings.load(preferences))) return false;
        try {
            NetworkCapabilities capabilities = connectivity.getNetworkCapabilities(network);
            if (capabilities == null || !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                    || !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return false;
            WifiIdentity identity = wifiIdentity;
            if (identity != null && network.equals(identity.network())) {
                if (identity.lost()) return false;
                if (Build.VERSION.SDK_INT >= 31 && identity.ssid() != null) {
                    return settings.ssid().equals(identity.ssid());
                }
            }
            return settings.ssid().equals(legacySsid());
        } catch (SecurityException missing) {
            return false;
        }
    }

    @SuppressWarnings("deprecation")
    private String legacySsid() {
        WifiManager wifi = context.getApplicationContext().getSystemService(WifiManager.class);
        WifiInfo info = wifi.getConnectionInfo();
        return info == null ? null : canonicalSsid(info.getSSID());
    }

    private static String canonicalSsid(String ssid) {
        if (ssid == null || WifiManager.UNKNOWN_SSID.equals(ssid)) return null;
        if (ssid.length() >= 2 && ssid.charAt(0) == '"' && ssid.charAt(ssid.length() - 1) == '"') {
            return ssid.substring(1, ssid.length() - 1);
        }
        return ssid;
    }

    static boolean canReadSsid(Context context) {
        return context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
                && context.checkSelfPermission(Manifest.permission.ACCESS_BACKGROUND_LOCATION) == PackageManager.PERMISSION_GRANTED
                && context.getSystemService(LocationManager.class).isLocationEnabled();
    }

    void stop() {
        disable(R.string.ftp_off);
    }

    private void disable(int reason) {
        closeProxy();
        FirewallStatus.postFtp(context.getString(reason));
    }

    private void closeProxy() {
        if (proxy != null) proxy.close();
        proxy = null;
        current = null;
    }
}
