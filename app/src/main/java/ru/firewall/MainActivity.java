package ru.firewall;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Insets;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.view.inputmethod.InputMethodManager;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.Switch;
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
    private static final int VPN_PERMISSION = 21;
    private static final int NOTIFICATION_PERMISSION = 22;
    private static final int RULE_COLUMN_WIDTH = 48;
    private static final int LIST_PADDING = 12;
    private static final String SHOW_SYSTEM_APPS = "show_system_apps";

    private record InstalledApp(String label, String packageName, String description, boolean system) {}

    private final ExecutorService loader = Executors.newSingleThreadExecutor();
    private List<InstalledApp> installedApps = Collections.emptyList();
    private RuleStore rules;
    private RuleAdapter adapter;
    private EditText search;
    private TextView empty;
    private RadioGroup tabs;
    private boolean showSystemApps;
    private TextView firewallStatus;
    private Button power;
    private SharedPreferences rulePreferences;
    private final Runnable statusChanged = this::updateFirewallControls;
    private final SharedPreferences.OnSharedPreferenceChangeListener rulesChanged
            = (preferences, key) -> adapter.notifyDataSetChanged();

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        rules = new RuleStore(this);
        rulePreferences = getSharedPreferences(RuleStore.PREFERENCES, MODE_PRIVATE);
        SharedPreferences display = getSharedPreferences("display_settings", MODE_PRIVATE);
        showSystemApps = display.getBoolean(SHOW_SYSTEM_APPS, true);
        LinearLayout root = column();
        root.setBackgroundColor(Color.WHITE);
        if (Build.VERSION.SDK_INT >= 30) {
            getWindow().setDecorFitsSystemWindows(false);
            int lightBars = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                    | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
            getWindow().getInsetsController().setSystemBarsAppearance(lightBars, lightBars);
            root.setOnApplyWindowInsetsListener((view, insets) -> {
                Insets padding = insets.getInsets(WindowInsets.Type.systemBars()
                        | WindowInsets.Type.displayCutout() | WindowInsets.Type.ime());
                view.setPadding(padding.left, padding.top, padding.right, padding.bottom);
                return insets;
            });
        } else {
            root.setFitsSystemWindows(true);
        }

        firewallStatus = text(24);
        firewallStatus.setAccessibilityHeading(true);
        firewallStatus.setPadding(dp(16), dp(12), dp(16), dp(8));
        root.addView(firewallStatus);

        tabs = new RadioGroup(this);
        tabs.setOrientation(LinearLayout.HORIZONTAL);
        tabs.setPadding(dp(8), 0, dp(8), dp(4));
        tabs.addView(tab(R.id.tab_firewall, R.string.tab_firewall));
        tabs.addView(tab(R.id.tab_programs, R.string.tab_programs));
        root.addView(tabs);

        View settings = createSettings(display);
        View programs = createPrograms(state);
        root.addView(settings, new LinearLayout.LayoutParams(-1, 0, 1));
        root.addView(programs, new LinearLayout.LayoutParams(-1, 0, 1));

        tabs.setOnCheckedChangeListener((group, checkedId) -> {
            boolean showPrograms = checkedId == R.id.tab_programs;
            if (!showPrograms && search.hasFocus()) {
                getSystemService(InputMethodManager.class)
                        .hideSoftInputFromWindow(search.getWindowToken(), 0);
                search.clearFocus();
            }
            settings.setVisibility(showPrograms ? View.GONE : View.VISIBLE);
            programs.setVisibility(showPrograms ? View.VISIBLE : View.GONE);
        });
        tabs.check(state != null && state.getBoolean("programs_tab")
                ? R.id.tab_programs : R.id.tab_firewall);
        root.setFocusableInTouchMode(true);
        setContentView(root);
        root.requestFocus();
        updateFirewallControls();
    }

    @Override protected void onStart() {
        super.onStart();
        FirewallStatus.addListener(statusChanged);
        rulePreferences.registerOnSharedPreferenceChangeListener(rulesChanged);
        updateFirewallControls();
    }

    @Override protected void onStop() {
        FirewallStatus.removeListener(statusChanged);
        rulePreferences.unregisterOnSharedPreferenceChangeListener(rulesChanged);
        super.onStop();
    }

    private void updateFirewallControls() {
        FirewallStatus.State state = FirewallStatus.current();
        firewallStatus.setText(switch (state) {
            case OFF -> R.string.firewall_off;
            case STARTING -> R.string.firewall_starting;
            case ACTIVE -> R.string.firewall_on;
            case NO_NETWORK -> R.string.firewall_no_network;
            case ERROR -> R.string.firewall_error;
        });
        boolean enabled = state == FirewallStatus.State.STARTING || state == FirewallStatus.State.ACTIVE
                || state == FirewallStatus.State.NO_NETWORK || FirewallService.wantsFirewall(this);
        power.setText(enabled ? R.string.disable_firewall : R.string.enable_firewall);
        power.setOnClickListener(view -> {
            if (enabled) FirewallService.requestStop(this);
            else beginFirewallPermission();
        });
    }

    private void beginFirewallPermission() {
        Intent consent = VpnService.prepare(this);
        if (consent != null) {
            startActivityForResult(consent, VPN_PERMISSION);
        } else {
            startFirewall();
        }
    }

    private void startFirewall() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, NOTIFICATION_PERMISSION);
        } else {
            FirewallService.requestStart(this);
        }
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_PERMISSION && resultCode == RESULT_OK) startFirewall();
    }

    @Override public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grants) {
        super.onRequestPermissionsResult(requestCode, permissions, grants);
        if (requestCode == NOTIFICATION_PERMISSION) FirewallService.requestStart(this);
    }

    private RadioButton tab(int id, int title) {
        RadioButton tab = new RadioButton(this);
        tab.setId(id);
        tab.setText(title);
        tab.setTextSize(15);
        tab.setTextColor(getColorStateList(R.color.tab_text));
        tab.setButtonDrawable((Drawable) null);
        tab.setBackgroundResource(R.drawable.tab_background);
        tab.setGravity(Gravity.CENTER);
        tab.setMinHeight(dp(48));
        RadioGroup.LayoutParams params = new RadioGroup.LayoutParams(0, -2, 1);
        params.setMargins(dp(4), 0, dp(4), 0);
        tab.setLayoutParams(params);
        return tab;
    }

    private View createSettings(SharedPreferences display) {
        ScrollView scroll = new ScrollView(this);
        LinearLayout settings = column();
        settings.setPadding(dp(16), dp(12), dp(16), dp(16));
        scroll.addView(settings);

        power = new Button(this);
        power.setAllCaps(false);
        settings.addView(power, new LinearLayout.LayoutParams(-1, -2));

        Button vpnSettings = new Button(this);
        vpnSettings.setText(R.string.vpn_settings);
        vpnSettings.setAllCaps(false);
        vpnSettings.setOnClickListener(view -> startActivity(new Intent(Settings.ACTION_VPN_SETTINGS)));
        settings.addView(vpnSettings, new LinearLayout.LayoutParams(-1, -2));

        TextView help = text(14);
        help.setText(R.string.vpn_settings_help);
        help.setPadding(0, dp(4), 0, dp(16));
        settings.addView(help);

        Switch systemApps = new Switch(this);
        systemApps.setText(R.string.show_system_apps);
        systemApps.setTextSize(16);
        systemApps.setMinHeight(dp(48));
        systemApps.setSwitchPadding(dp(12));
        systemApps.setChecked(showSystemApps);
        systemApps.setOnCheckedChangeListener((view, checked) -> {
            showSystemApps = checked;
            display.edit().putBoolean(SHOW_SYSTEM_APPS, checked).apply();
            filterApps(search.getText().toString());
        });
        settings.addView(systemApps, new LinearLayout.LayoutParams(-1, -2));
        return scroll;
    }

    private View createPrograms(Bundle state) {
        LinearLayout programs = column();
        search = new EditText(this);
        search.setSingleLine(true);
        search.setHint(R.string.search_apps);
        search.setId(View.generateViewId());
        if (state != null) search.setText(state.getString("query", ""));
        LinearLayout.LayoutParams searchLayout = new LinearLayout.LayoutParams(-1, -2);
        searchLayout.setMargins(dp(16), 0, dp(16), dp(4));
        programs.addView(search, searchLayout);
        programs.addView(ruleHeader());

        ListView list = new ListView(this);
        adapter = new RuleAdapter();
        list.setItemsCanFocus(true);
        list.setAdapter(adapter);
        list.setDivider(new ColorDrawable(getColor(R.color.rule_divider)));
        list.setDividerHeight(dp(1));
        programs.addView(list, new LinearLayout.LayoutParams(-1, 0, 1));

        empty = text(16);
        empty.setGravity(Gravity.CENTER);
        empty.setText(R.string.loading_apps);
        programs.addView(empty, new LinearLayout.LayoutParams(-1, 0, 1));
        list.setEmptyView(empty);
        search.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence value, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence value, int start, int before, int count) {
                filterApps(value.toString());
            }
            @Override public void afterTextChanged(Editable value) {}
        });
        return programs;
    }

    private View ruleHeader() {
        LinearLayout header = new LinearLayout(this);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setPaddingRelative(dp(LIST_PADDING), 0, dp(LIST_PADDING), 0);
        addColumnIcon(header, R.drawable.ic_wifi, R.string.wifi);
        addColumnIcon(header, R.drawable.ic_mobile, R.string.mobile);
        addColumnIcon(header, R.drawable.ic_exclusion, R.string.exclude);
        return header;
    }

    private void addColumnIcon(LinearLayout header, int icon, int title) {
        ImageView image = new ImageView(this);
        image.setImageResource(icon);
        image.setScaleType(ImageView.ScaleType.CENTER);
        image.setContentDescription(getString(title));
        header.addView(image, new LinearLayout.LayoutParams(dp(RULE_COLUMN_WIDTH), dp(36)));
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
        out.putBoolean("programs_tab", tabs.getCheckedRadioButtonId() == R.id.tab_programs);
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
            CharSequence description = app.loadDescription(packages);
            result.add(new InstalledApp(app.loadLabel(packages).toString(), app.packageName,
                    description == null || description.toString().trim().isEmpty()
                            ? app.packageName : description.toString(),
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
            if (!showSystemApps && app.system()) continue;
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
        private final LinearLayout root = new LinearLayout(MainActivity.this);
        private final LinearLayout details = column();
        private final TextView label = text(16);
        private final TextView description = text(13);
        private final CheckBox wifi = control();
        private final CheckBox mobile = control();
        private final CheckBox excluded = control();

        RuleRow() {
            root.setTag(this);
            root.setGravity(Gravity.CENTER_VERTICAL);
            root.setPaddingRelative(dp(LIST_PADDING), dp(4), dp(LIST_PADDING), dp(4));
            for (CheckBox box : new CheckBox[] {wifi, mobile, excluded}) {
                root.addView(box, new LinearLayout.LayoutParams(dp(RULE_COLUMN_WIDTH), -2));
            }

            details.setGravity(Gravity.CENTER_VERTICAL);
            details.setMinimumHeight(dp(52));
            details.setPadding(dp(12), dp(6), dp(12), dp(6));
            label.setMaxLines(2);
            label.setEllipsize(TextUtils.TruncateAt.END);
            description.setMaxLines(2);
            description.setEllipsize(TextUtils.TruncateAt.END);
            description.setTextColor(getColor(R.color.secondary_text));
            details.addView(label);
            details.addView(description);
            root.addView(details, new LinearLayout.LayoutParams(0, -2, 1));
        }

        void bind(InstalledApp app) {
            label.setText(app.label());
            description.setText(app.description());
            NetworkRules current = rules.read(app.packageName());
            bindNetwork(app, NetworkType.WIFI, wifi, R.string.wifi, current.getWifi(), current.getExcluded());
            bindNetwork(app, NetworkType.MOBILE, mobile, R.string.mobile, current.getMobile(), current.getExcluded());

            excluded.setChecked(current.getExcluded());
            excluded.setButtonDrawable(current.getExcluded() ? R.drawable.rule_allowed : R.drawable.rule_undecided);
            excluded.setContentDescription(getString(R.string.app_control, app.label(), getString(R.string.exclude)));
            excluded.setOnClickListener(view -> {
                rules.setExcluded(app.packageName(), excluded.isChecked());
                bind(app);
            });
            details.setBackgroundColor(getColor(ruleBackground(current)));
        }

        private int ruleBackground(NetworkRules current) {
            if (current.getExcluded()) return R.color.rule_excluded_background;
            AccessRule wifiRule = current.getWifi();
            AccessRule mobileRule = current.getMobile();
            if (wifiRule == AccessRule.UNDECIDED || mobileRule == AccessRule.UNDECIDED) {
                return android.R.color.white;
            }
            if (wifiRule != mobileRule) return R.color.rule_mixed_background;
            return wifiRule == AccessRule.ALLOWED
                    ? R.color.rule_allowed_background : R.color.rule_denied_background;
        }

        private void bindNetwork(InstalledApp app, NetworkType network, CheckBox box,
                                 int title, AccessRule value, boolean bypass) {
            int description = switch (value) {
                case UNDECIDED -> R.string.undecided;
                case ALLOWED -> R.string.allowed;
                case DENIED -> R.string.denied;
            };
            String controlName = getString(R.string.app_control, app.label(), getString(title));
            String state = bypass
                    ? getString(R.string.rule_excluded_state, getString(description)) : getString(description);
            if (Build.VERSION.SDK_INT >= 30) {
                box.setContentDescription(controlName);
                box.setStateDescription(state);
            } else {
                box.setContentDescription(getString(R.string.app_control, controlName, state));
            }
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

    private CheckBox control() {
        CheckBox value = new CheckBox(this);
        value.setButtonTintList(null);
        value.setPaddingRelative(dp((RULE_COLUMN_WIDTH - 24) / 2), 0, 0, 0);
        value.setMinHeight(dp(48));
        return value;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
