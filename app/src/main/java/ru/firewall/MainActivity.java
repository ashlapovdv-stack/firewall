package ru.firewall;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Insets;
import android.os.Build;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.BaseAdapter;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;

import java.text.Collator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import ru.firewall.policy.AccessRule;
import ru.firewall.policy.NetworkRules;
import ru.firewall.policy.NetworkType;

public final class MainActivity extends Activity {
    private record InstalledApp(String label, String packageName, boolean system) {}

    private final ExecutorService loader = Executors.newSingleThreadExecutor();
    private List<InstalledApp> installedApps = Collections.emptyList();
    private RuleStore rules;
    private RuleAdapter adapter;
    private EditText search;
    private TextView empty;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        rules = new RuleStore(this);
        LinearLayout root = column();
        root.setBackgroundColor(Color.WHITE);
        if (Build.VERSION.SDK_INT >= 30) {
            getWindow().setDecorFitsSystemWindows(false);
            root.setOnApplyWindowInsetsListener((view, insets) -> {
                Insets padding = insets.getInsets(WindowInsets.Type.systemBars()
                        | WindowInsets.Type.displayCutout() | WindowInsets.Type.ime());
                view.setPadding(padding.left, padding.top, padding.right, padding.bottom);
                return insets;
            });
        } else {
            root.setFitsSystemWindows(true);
        }

        TextView title = text(25);
        title.setText(R.string.app_name);
        title.setAccessibilityHeading(true);
        title.setPadding(dp(16), dp(12), dp(16), dp(4));
        root.addView(title);

        TextView status = text(14);
        status.setText(R.string.configuration_status);
        status.setPadding(dp(16), 0, dp(16), dp(6));
        root.addView(status);

        search = new EditText(this);
        search.setSingleLine(true);
        search.setHint(R.string.search_apps);
        search.setId(View.generateViewId());
        if (state != null) search.setText(state.getString("query", ""));
        LinearLayout.LayoutParams searchLayout = new LinearLayout.LayoutParams(-1, -2);
        searchLayout.setMargins(dp(16), 0, dp(16), dp(4));
        root.addView(search, searchLayout);
        root.setFocusableInTouchMode(true);
        root.requestFocus();

        ListView list = new ListView(this);
        adapter = new RuleAdapter();
        list.setItemsCanFocus(true);
        list.setAdapter(adapter);
        root.addView(list, new LinearLayout.LayoutParams(-1, 0, 1));

        empty = text(16);
        empty.setGravity(Gravity.CENTER);
        empty.setText(R.string.loading_apps);
        root.addView(empty, new LinearLayout.LayoutParams(-1, 0, 1));
        list.setEmptyView(empty);
        search.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence value, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence value, int start, int before, int count) {
                filterApps(value.toString());
            }
            @Override public void afterTextChanged(Editable value) {}
        });
        setContentView(root);
    }

    @Override
    protected void onResume() {
        super.onResume();
        loader.execute(() -> {
            List<InstalledApp> refreshed = loadApps();
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                installedApps = refreshed;
                empty.setText(R.string.no_matching_apps);
                filterApps(search.getText().toString());
            });
        });
    }

    @Override
    protected void onSaveInstanceState(Bundle out) {
        out.putString("query", search.getText().toString());
        super.onSaveInstanceState(out);
    }

    @Override
    protected void onDestroy() {
        loader.shutdownNow();
        super.onDestroy();
    }

    @SuppressWarnings("deprecation")
    private List<InstalledApp> loadApps() {
        PackageManager packages = getPackageManager();
        List<ApplicationInfo> applications = Build.VERSION.SDK_INT >= 33
                ? packages.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
                : packages.getInstalledApplications(0);
        List<InstalledApp> result = new ArrayList<>(applications.size());
        for (ApplicationInfo app : applications) {
            if (getPackageName().equals(app.packageName)) continue;
            result.add(new InstalledApp(app.loadLabel(packages).toString(), app.packageName,
                    (app.flags & ApplicationInfo.FLAG_SYSTEM) != 0));
        }
        Collator order = Collator.getInstance();
        result.sort((first, second) -> {
            int group = Boolean.compare(first.system(), second.system());
            if (group != 0) return group;
            int label = order.compare(first.label(), second.label());
            return label != 0 ? label : first.packageName().compareTo(second.packageName());
        });
        return result;
    }

    private void filterApps(String query) {
        String term = query.trim().toLowerCase(Locale.ROOT);
        List<InstalledApp> matches = new ArrayList<>();
        for (InstalledApp app : installedApps) {
            if (app.label().toLowerCase(Locale.ROOT).contains(term)
                    || app.packageName().toLowerCase(Locale.ROOT).contains(term)) {
                matches.add(app);
            }
        }
        adapter.apps = matches;
        adapter.notifyDataSetChanged();
    }

    private final class RuleAdapter extends BaseAdapter {
        private List<InstalledApp> apps = Collections.emptyList();

        @Override public int getCount() { return apps.size(); }
        @Override public InstalledApp getItem(int position) { return apps.get(position); }
        @Override public long getItemId(int position) { return position; }

        @Override
        public View getView(int position, View recycled, ViewGroup parent) {
            RuleRow row = recycled == null ? new RuleRow() : (RuleRow) recycled.getTag();
            row.bind(getItem(position));
            return row.root;
        }
    }

    private final class RuleRow {
        private final LinearLayout root = column();
        private final TextView label = text(16);
        private final TextView packageName = text(12);
        private final CheckBox wifi = control(R.string.wifi);
        private final CheckBox mobile = control(R.string.mobile);
        private final CheckBox excluded = control(R.string.exclude);

        RuleRow() {
            root.setTag(this);
            root.setPadding(dp(16), dp(8), dp(16), dp(4));
            root.addView(label);
            root.addView(packageName);

            LinearLayout controls = new LinearLayout(MainActivity.this);
            for (CheckBox box : new CheckBox[] {wifi, mobile, excluded}) {
                controls.addView(box, new LinearLayout.LayoutParams(0, -2, 1));
            }
            root.addView(controls);
        }

        void bind(InstalledApp app) {
            label.setText(app.label());
            packageName.setText(app.packageName());
            NetworkRules current = rules.read(app.packageName());
            bindNetwork(app, NetworkType.WIFI, wifi, R.string.wifi, current.getWifi(), current.getExcluded());
            bindNetwork(app, NetworkType.MOBILE, mobile, R.string.mobile, current.getMobile(), current.getExcluded());

            excluded.setChecked(current.getExcluded());
            excluded.setContentDescription(app.label() + ", " + getString(R.string.exclude));
            excluded.setOnClickListener(view -> {
                rules.setExcluded(app.packageName(), excluded.isChecked());
                bind(app);
            });
        }

        private void bindNetwork(InstalledApp app, NetworkType network, CheckBox box,
                                 int title, AccessRule value, boolean bypass) {
            int description = switch (value) {
                case UNDECIDED -> R.string.undecided;
                case ALLOWED -> R.string.allowed;
                case DENIED -> R.string.denied;
            };
            box.setContentDescription(app.label() + ", " + getString(title) + ", "
                    + getString(description) + (bypass ? ". " + getString(R.string.excluded_help) : ""));
            box.setChecked(value == AccessRule.ALLOWED);
            box.setButtonDrawable(switch (value) {
                case UNDECIDED -> R.drawable.rule_undecided;
                case ALLOWED -> R.drawable.rule_allowed;
                case DENIED -> R.drawable.rule_denied;
            });
            box.setEnabled(!bypass);
            box.setOnClickListener(view -> {
                AccessRule next = switch (value) {
                    case UNDECIDED -> AccessRule.ALLOWED;
                    case ALLOWED -> AccessRule.DENIED;
                    case DENIED -> AccessRule.UNDECIDED;
                };
                rules.setRule(app.packageName(), network, next);
                bind(app);
            });
        }
    }

    private LinearLayout column() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        return layout;
    }

    private TextView text(int size) {
        TextView value = new TextView(this);
        value.setTextSize(size);
        value.setTextColor(0xff20252b);
        return value;
    }

    private CheckBox control(int title) {
        CheckBox value = new CheckBox(this);
        value.setText(title);
        value.setTextSize(13);
        value.setMinHeight(dp(48));
        return value;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
