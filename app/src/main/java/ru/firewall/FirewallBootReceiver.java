package ru.firewall;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;

public final class FirewallBootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())
                && FirewallService.wantsFirewall(context) && VpnService.prepare(context) == null) {
            FirewallService.requestStart(context);
        }
    }
}
