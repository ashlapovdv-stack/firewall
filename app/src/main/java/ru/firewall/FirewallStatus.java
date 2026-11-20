package ru.firewall;

import android.os.Handler;
import android.os.Looper;

import java.util.LinkedHashSet;
import java.util.Set;

final class FirewallStatus {
    enum State { OFF, STARTING, ACTIVE, NO_NETWORK, ERROR }

    private static final Handler main = new Handler(Looper.getMainLooper());
    private static final Set<Runnable> listeners = new LinkedHashSet<>();
    private static State state = State.OFF;

    private FirewallStatus() {}

    static void addListener(Runnable listener) {
        listeners.add(listener);
    }

    static void removeListener(Runnable listener) {
        listeners.remove(listener);
    }

    static State current() {
        return state;
    }

    static void post(State updated) {
        main.post(() -> {
            if (state == updated) return;
            state = updated;
            for (Runnable listener : listeners) listener.run();
        });
    }
}
