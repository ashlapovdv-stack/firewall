package ru.firewall;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public final class FirewallDecisionReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        FirewallService.handleDecision(intent);
    }
}
