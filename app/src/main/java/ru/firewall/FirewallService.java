package ru.firewall;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.InetAddresses;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.ParcelFileDescriptor;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import ru.firewall.policy.AccessDecision;
import ru.firewall.policy.AccessRule;
import ru.firewall.policy.NetworkType;

public final class FirewallService extends VpnService {
    private static final String START = "ru.firewall.action.START";
    private static final String STOP = "ru.firewall.action.STOP";
    private static final String DECIDE = "ru.firewall.action.DECIDE";
    private static final String SERVICE_CHANNEL = "firewall_service";
    private static final String DECISION_CHANNEL = "firewall_decisions";
    private static final int SERVICE_NOTIFICATION = 1;
    private static final int DECISION_NOTIFICATION = 2;
    private static final int MTU = 1500;
    private static FirewallService running;

    private record RuleTarget(String app, NetworkType network) {}
    private record Prompt(RuleTarget target, int uid, String token) {}
    private record Upstream(Network network, NetworkType type, List<InetAddress> dns, boolean lockdown) {}
    private final Map<RuleTarget, Prompt> prompts = new HashMap<>();
    private final AtomicBoolean rulesDirty = new AtomicBoolean(true);
    private final Handler main = new Handler(android.os.Looper.getMainLooper());
    private final Runnable rebuildTask = this::rebuild;
    private final SharedPreferences.OnSharedPreferenceChangeListener ruleChange = (prefs, key) -> {
        removeResolvedPrompts();
        rulesDirty.set(true);
        queueRebuild();
    };
    private final BroadcastReceiver packagesAdded = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            Uri data = intent.getData();
            if (Intent.ACTION_PACKAGE_ADDED.equals(intent.getAction()) && data != null) {
                handlePackageChange(data.getSchemeSpecificPart());
            }
        }
    };
    private final ConnectivityManager.NetworkCallback networkChange = new ConnectivityManager.NetworkCallback() {
        @Override public void onAvailable(Network network) { queueRebuild(); }
        @Override public void onLost(Network network) { queueRebuild(); }
        @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities caps) { queueRebuild(); }
        @Override public void onLinkPropertiesChanged(Network network, LinkProperties properties) { queueRebuild(); }
    };

    private ConnectivityManager connectivity;
    private NotificationManager notifications;
    private SharedPreferences rulePreferences;
    private RuleStore rules;
    private HandlerThread workerThread;
    private Handler worker;
    private boolean callbackRegistered;
    private boolean packageReceiverRegistered;
    private volatile boolean stopping;
    // The worker owns the interface and native engine.
    private ParcelFileDescriptor device;
    private long nativeHandle;
    private Upstream activeUpstream;

    static boolean wantsFirewall(Context context) {
        return settings(context).getBoolean("enabled", false);
    }

    private static SharedPreferences settings(Context context) {
        return context.getSharedPreferences("firewall_service", MODE_PRIVATE);
    }

    static void requestStart(Context context) {
        try {
            context.startForegroundService(new Intent(context, FirewallService.class).setAction(START));
        } catch (IllegalStateException | SecurityException denied) {
            FirewallStatus.post(FirewallStatus.State.ERROR);
        }
    }

    static void requestStop(Context context) {
        settings(context).edit().putBoolean("enabled", false).apply();
        if (running != null) running.shutdown(FirewallStatus.State.OFF);
    }

    static void handleDecision(Intent intent) {
        if (running != null) running.applyDecision(intent);
    }

    static void handlePackageChange(String packageName) {
        if (running == null || packageName == null || packageName.isEmpty()) return;
        for (NetworkType network : NetworkType.values()) {
            running.clearPrompt(new RuleTarget(packageName, network));
        }
        running.rulesDirty.set(true);
        running.queueRebuild();
    }

    @Override public void onCreate() {
        super.onCreate();
        connectivity = getSystemService(ConnectivityManager.class);
        notifications = getSystemService(NotificationManager.class);
        rules = new RuleStore(this);
        rulePreferences = getSharedPreferences(RuleStore.PREFERENCES, MODE_PRIVATE);
        workerThread = new HandlerThread("firewall-vpn");
        workerThread.start();
        worker = new Handler(workerThread.getLooper());
        notifications.createNotificationChannel(new NotificationChannel(SERVICE_CHANNEL,
                getString(R.string.service_channel), NotificationManager.IMPORTANCE_LOW));
        notifications.createNotificationChannel(new NotificationChannel(DECISION_CHANNEL,
                getString(R.string.decision_channel), NotificationManager.IMPORTANCE_DEFAULT));
        for (var existing : notifications.getActiveNotifications()) {
            if (existing.getId() == DECISION_NOTIFICATION) {
                notifications.cancel(existing.getTag(), existing.getId());
            }
        }
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (STOP.equals(action)) {
            requestStop(this);
            stopSelf();
            return START_NOT_STICKY;
        }
        if (!START.equals(action) && !SERVICE_INTERFACE.equals(action)
                && !wantsFirewall(this) && !isAlwaysOn()) {
            stopSelf();
            return START_NOT_STICKY;
        }
        if (running == this && !stopping) return START_STICKY;
        if (stopping) return START_NOT_STICKY;
        if (prepare(this) != null) {
            settings(this).edit().putBoolean("enabled", false).apply();
            shutdown(FirewallStatus.State.ERROR);
            return START_NOT_STICKY;
        }
        try {
            Notification status = statusNotification(R.string.firewall_starting);
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(SERVICE_NOTIFICATION, status, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
            } else {
                startForeground(SERVICE_NOTIFICATION, status);
            }
            running = this;
            settings(this).edit().putBoolean("enabled", true).apply();
            rulePreferences.registerOnSharedPreferenceChangeListener(ruleChange);
            connectivity.registerDefaultNetworkCallback(networkChange, worker);
            callbackRegistered = true;
            IntentFilter packages = new IntentFilter(Intent.ACTION_PACKAGE_ADDED);
            packages.addDataScheme("package");
            if (Build.VERSION.SDK_INT >= 33) {
                registerReceiver(packagesAdded, packages, Context.RECEIVER_NOT_EXPORTED);
            } else {
                registerReceiver(packagesAdded, packages);
            }
            packageReceiverRegistered = true;
            FirewallStatus.post(FirewallStatus.State.STARTING);
            queueRebuild();
            return START_STICKY;
        } catch (IllegalStateException | SecurityException denied) {
            shutdown(FirewallStatus.State.ERROR);
            return START_NOT_STICKY;
        }
    }

    private void queueRebuild() {
        if (stopping) return;
        worker.removeCallbacks(rebuildTask);
        worker.post(rebuildTask);
    }

    private void rebuild() {
        if (stopping) return;
        ParcelFileDescriptor replacement = null;
        try {
            Network underlying = connectivity.getActiveNetwork();
            NetworkType type = underlying == null ? null
                    : networkType(connectivity.getNetworkCapabilities(underlying));
            LinkProperties link = type == null ? null : connectivity.getLinkProperties(underlying);
            List<InetAddress> dns = link == null ? Collections.emptyList() : link.getDnsServers().stream()
                    .filter(server -> !server.isLinkLocalAddress()).collect(Collectors.toList());
            Upstream selected = new Upstream(underlying, type, dns, isLockdownEnabled());
            boolean force = rulesDirty.getAndSet(false);
            if (nativeHandle != 0 && !force && selected.equals(activeUpstream)) return;
            closeEngine();

            Network[] upstream = type == null ? new Network[0] : new Network[]{underlying};
            Builder builder = new Builder()
                    .setSession(getString(R.string.app_name))
                    .setConfigureIntent(openActivity())
                    .setMtu(MTU)
                    .setUnderlyingNetworks(upstream)
                    .addAddress("10.111.222.1", 32)
                    .addAddress("fd73:5d35:e933:1::1", 128)
                    .addRoute("0.0.0.0", 0)
                    .addRoute("::", 0)
                    .addDisallowedApplication(getPackageName());

            if (!selected.lockdown()) addExcludedApplications(builder);
            for (InetAddress server : selected.dns()) builder.addDnsServer(server);
            replacement = builder.establish();
            if (replacement == null) throw new IOException("VPN interface unavailable");
            closeDevice();
            device = replacement;
            replacement = null;
            nativeHandle = NativeTunnel.open(device.getFd(), MTU, new FlowPolicy(underlying, type));
            if (nativeHandle == 0) throw new IOException("VPN engine unavailable");
            activeUpstream = selected;
            report(type == null ? FirewallStatus.State.NO_NETWORK : FirewallStatus.State.ACTIVE,
                    type == null ? R.string.firewall_no_network : R.string.firewall_on);
        } catch (IOException | PackageManager.NameNotFoundException | RuntimeException | LinkageError failure) {
            close(replacement);
            report(FirewallStatus.State.ERROR, R.string.firewall_error);
            if (!stopping) worker.postDelayed(rebuildTask, 5000);
        }
    }

    private void addExcludedApplications(Builder builder) {
        PackageManager packages = getPackageManager();
        for (ApplicationInfo info : installedApplications(packages)) {
            if (getPackageName().equals(info.packageName) || !rules.read(info.packageName).getExcluded()) continue;
            String[] group = packages.getPackagesForUid(info.uid);
            if (group == null || group.length == 0) continue;
            boolean excluded = true;
            for (String app : group) excluded &= rules.read(app).getExcluded();
            if (!excluded) continue;
            try {
                builder.addDisallowedApplication(info.packageName);
            } catch (PackageManager.NameNotFoundException removed) {
                // The package disappeared while the list was being scanned.
            }
        }
    }

    @SuppressWarnings("deprecation")
    private static List<ApplicationInfo> installedApplications(PackageManager packages) {
        return Build.VERSION.SDK_INT >= 33
                ? packages.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
                : packages.getInstalledApplications(0);
    }

    private static NetworkType networkType(NetworkCapabilities caps) {
        if (caps == null || !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return null;
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return NetworkType.WIFI;
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ? NetworkType.MOBILE : null;
    }

    private final class FlowPolicy implements NativeTunnel.Policy {
        private final Network network;
        private final NetworkType type;

        FlowPolicy(Network network, NetworkType type) {
            this.network = network;
            this.type = type;
        }

        @Override public boolean allowFlow(int protocol, String local, int localPort,
                                          String remote, int remotePort) {
            if (stopping || type == null || !network.equals(connectivity.getActiveNetwork())) return false;
            int uid;
            try {
                uid = connectivity.getConnectionOwnerUid(protocol,
                        new InetSocketAddress(InetAddresses.parseNumericAddress(local), localPort),
                        new InetSocketAddress(InetAddresses.parseNumericAddress(remote), remotePort));
            } catch (IllegalArgumentException | SecurityException notOwned) {
                return false;
            }
            if (uid < 0) return false;
            String[] apps = getPackageManager().getPackagesForUid(uid);
            if (apps == null || apps.length == 0) return false;
            boolean allow = true;
            boolean allExcluded = true;
            for (String app : apps) {
                AccessDecision decision = rules.read(app).decide(type);
                allExcluded &= decision == AccessDecision.BYPASS;
                if (decision == AccessDecision.BLOCK_AND_NOTIFY) {
                    main.post(() -> offerRule(new RuleTarget(app, type), uid, network));
                }
                allow &= decision == AccessDecision.ALLOW || decision == AccessDecision.BYPASS;
            }
            // Lockdown forbids direct exclusion. Do not silently proxy an excluded UID.
            return allow && !allExcluded;
        }

        @Override public boolean protectSocket(int fd) {
            if (stopping || type == null || !network.equals(connectivity.getActiveNetwork()) || !protect(fd)) {
                return false;
            }
            try (ParcelFileDescriptor socket = ParcelFileDescriptor.fromFd(fd)) {
                network.bindSocket(socket.getFileDescriptor());
                return true;
            } catch (IOException | RuntimeException unavailable) {
                return false;
            }
        }
    }

    private void offerRule(RuleTarget target, int uid, Network network) {
        if (stopping || !network.equals(connectivity.getActiveNetwork())
                || rules.read(target.app()).decide(target.network()) != AccessDecision.BLOCK_AND_NOTIFY
                || prompts.containsKey(target) || prompts.size() >= 24
                || (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) || !notifications.areNotificationsEnabled()) return;

        try {
            ApplicationInfo app = getApplicationInfo(target.app());
            if (app.uid != uid) return;
            Prompt prompt = new Prompt(target, uid, UUID.randomUUID().toString());
            String label = app.loadLabel(getPackageManager()).toString();
            Notification request = new Notification.Builder(this, DECISION_CHANNEL)
                    .setSmallIcon(R.drawable.ic_firewall)
                    .setContentTitle(label)
                    .setContentText(getString(R.string.decision_message, networkLabel(target.network())))
                    .setContentIntent(openActivity())
                    .addAction(new Notification.Action.Builder(null, getString(R.string.allow_action),
                            decisionIntent(prompt, "ALLOWED")).build())
                    .addAction(new Notification.Action.Builder(null, getString(R.string.deny_action),
                            decisionIntent(prompt, "DENIED")).build())
                    .setDeleteIntent(decisionIntent(prompt, "DISMISSED"))
                    .setVisibility(Notification.VISIBILITY_PRIVATE)
                    .setOnlyAlertOnce(true)
                    .build();
            prompts.put(target, prompt);
            notifications.notify(notificationTag(target), DECISION_NOTIFICATION, request);
        } catch (PackageManager.NameNotFoundException removed) {
            // The package is no longer installed.
        }
    }

    private ApplicationInfo getApplicationInfo(String packageName) throws PackageManager.NameNotFoundException {
        return getPackageManager().getApplicationInfo(packageName, 0);
    }

    private void applyDecision(Intent intent) {
        Uri data = intent.getData();
        if (stopping || !DECIDE.equals(intent.getAction()) || data == null
                || !"firewall".equals(data.getScheme()) || !"decision".equals(data.getAuthority())) return;
        var segments = data.getPathSegments();
        if (segments.size() != 4) return;
        NetworkType network = switch (segments.get(1)) {
            case "WIFI" -> NetworkType.WIFI;
            case "MOBILE" -> NetworkType.MOBILE;
            default -> null;
        };
        AccessRule decision = switch (segments.get(3)) {
            case "ALLOWED" -> AccessRule.ALLOWED;
            case "DENIED" -> AccessRule.DENIED;
            default -> null;
        };
        if (network == null) return;
        RuleTarget target = new RuleTarget(segments.get(0), network);
        Prompt prompt = prompts.get(target);
        if (prompt == null || !prompt.token().equals(segments.get(2))) return;
        if ("DISMISSED".equals(segments.get(3))) {
            clearPrompt(target);
            return;
        }
        if (decision == null) return;
        try {
            if (getApplicationInfo(target.app()).uid == prompt.uid()
                    && rules.read(target.app()).decide(network) == AccessDecision.BLOCK_AND_NOTIFY) {
                rules.setRule(target.app(), network, decision);
            }
        } catch (PackageManager.NameNotFoundException removed) {
            // A decision for an uninstalled application is stale.
        }
        clearPrompt(target);
    }

    private PendingIntent decisionIntent(Prompt prompt, String actionValue) {
        RuleTarget target = prompt.target();
        Uri data = new Uri.Builder().scheme("firewall").authority("decision")
                .appendPath(target.app()).appendPath(target.network().name())
                .appendPath(prompt.token()).appendPath(actionValue).build();
        Intent action = new Intent(this, FirewallDecisionReceiver.class).setAction(DECIDE).setData(data);
        return PendingIntent.getBroadcast(this, 0, action, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_ONE_SHOT);
    }

    private void removeResolvedPrompts() {
        for (RuleTarget target : new ArrayList<>(prompts.keySet())) {
            if (rules.read(target.app()).decide(target.network()) != AccessDecision.BLOCK_AND_NOTIFY) {
                clearPrompt(target);
            }
        }
    }

    private void clearPrompt(RuleTarget target) {
        prompts.remove(target);
        notifications.cancel(notificationTag(target), DECISION_NOTIFICATION);
    }

    private static String notificationTag(RuleTarget target) {
        return target.app() + ":" + target.network().name();
    }

    private String networkLabel(NetworkType type) {
        return getString(type == NetworkType.WIFI ? R.string.wifi : R.string.mobile);
    }

    private PendingIntent openActivity() {
        return PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class),
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    private Notification statusNotification(int label) {
        PendingIntent stop = PendingIntent.getService(this, 0,
                new Intent(this, FirewallService.class).setAction(STOP), PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, SERVICE_CHANNEL)
                .setSmallIcon(R.drawable.ic_firewall)
                .setContentTitle(getString(label))
                .setContentIntent(openActivity())
                .setOngoing(true)
                .setShowWhen(false)
                .addAction(new Notification.Action.Builder(null, getString(R.string.disable_firewall), stop).build())
                .build();
    }

    private void report(FirewallStatus.State state, int text) {
        main.post(() -> {
            if (stopping) return;
            notifications.notify(SERVICE_NOTIFICATION, statusNotification(text));
            FirewallStatus.post(state);
        });
    }

    @Override public void onRevoke() {
        main.post(() -> {
            settings(this).edit().putBoolean("enabled", false).apply();
            shutdown(FirewallStatus.State.OFF);
        });
    }

    @Override public void onDestroy() {
        if (!stopping) shutdown(FirewallStatus.State.OFF);
        super.onDestroy();
    }

    private void shutdown(FirewallStatus.State state) {
        if (stopping) return;
        stopping = true;
        if (running == this) running = null;
        rulePreferences.unregisterOnSharedPreferenceChangeListener(ruleChange);
        if (callbackRegistered) connectivity.unregisterNetworkCallback(networkChange);
        if (packageReceiverRegistered) unregisterReceiver(packagesAdded);
        for (RuleTarget target : new ArrayList<>(prompts.keySet())) clearPrompt(target);
        worker.removeCallbacksAndMessages(null);
        worker.post(() -> {
            closeEngine();
            closeDevice();
            workerThread.quitSafely();
            main.post(() -> {
                stopForeground(STOP_FOREGROUND_REMOVE);
                stopSelf();
                if (running == null) FirewallStatus.post(state);
            });
        });
    }

    private void closeEngine() {
        if (nativeHandle != 0) {
            NativeTunnel.close(nativeHandle);
            nativeHandle = 0;
        }
    }

    private void closeDevice() {
        close(device);
        device = null;
    }

    private static void close(ParcelFileDescriptor fd) {
        if (fd == null) return;
        try {
            fd.close();
        } catch (IOException ignored) {
            // The descriptor can already be closed when the VPN is revoked.
        }
    }
}
