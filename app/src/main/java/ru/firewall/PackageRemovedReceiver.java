package ru.firewall;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;

public final class PackageRemovedReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        Uri data = intent.getData();
        if (Intent.ACTION_PACKAGE_FULLY_REMOVED.equals(intent.getAction()) && data != null) {
            String packageName = data.getSchemeSpecificPart();
            if (packageName != null && !packageName.isEmpty()) {
                new RuleStore(context).remove(packageName);
            }
        }
    }
}
