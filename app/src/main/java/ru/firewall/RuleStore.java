package ru.firewall;

import android.content.Context;
import android.content.SharedPreferences;

import ru.firewall.policy.AccessRule;
import ru.firewall.policy.NetworkRules;
import ru.firewall.policy.NetworkType;

final class RuleStore {
    private final SharedPreferences preferences;

    RuleStore(Context context) {
        preferences = context.getSharedPreferences("network_rules", Context.MODE_PRIVATE);
    }

    NetworkRules read(String packageName) {
        return new NetworkRules(
                readRule(key(packageName, NetworkType.WIFI)),
                readRule(key(packageName, NetworkType.MOBILE)),
                preferences.getBoolean(packageName + ":excluded", false));
    }

    void setRule(String packageName, NetworkType network, AccessRule rule) {
        preferences.edit().putString(key(packageName, network), rule.name()).apply();
    }

    void setExcluded(String packageName, boolean excluded) {
        preferences.edit().putBoolean(packageName + ":excluded", excluded).apply();
    }

    void remove(String packageName) {
        preferences.edit()
                .remove(key(packageName, NetworkType.WIFI))
                .remove(key(packageName, NetworkType.MOBILE))
                .remove(packageName + ":excluded")
                .apply();
    }

    private AccessRule readRule(String key) {
        String value = preferences.getString(key, AccessRule.UNDECIDED.name());
        try {
            return AccessRule.valueOf(value);
        } catch (IllegalArgumentException failure) {
            return AccessRule.DENIED;
        }
    }

    private static String key(String packageName, NetworkType network) {
        return packageName + ":" + network.name();
    }
}
