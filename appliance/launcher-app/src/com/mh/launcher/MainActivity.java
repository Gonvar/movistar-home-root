package com.mh.launcher;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.res.ColorStateList;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.TextUtils;
import android.text.format.DateFormat;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * MH Launcher - minimal appliance home screen for the Movistar Home box.
 *
 * Design goals: zero background work, zero dependencies, everything built in
 * memory at resume time, instant taps. Big clock + app grid.
 */
public class MainActivity extends Activity {

    private static final int COLS = 4;

    private static final int COL_CLOCK = 0xFFF3F6FA;
    private static final int COL_MUTED = 0xFF8593A6;
    private static final int COL_TILE = 0xFF171D27;
    private static final int COL_TILE_PRESS = 0xFF2A3547;
    private static final int COL_LABEL = 0xFFC6CFDC;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private TextView clockView;
    private TextView dateView;
    private TextView batteryView;
    private LinearLayout gridHolder;
    private boolean needReload = true;

    private final BroadcastReceiver pkgWatch = new BroadcastReceiver() {
        @Override
        public void onReceive(Context c, Intent i) {
            needReload = true;
        }
    };

    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            updateHeader();
            ui.postDelayed(this, 30000L);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildUi();
        IntentFilter f = new IntentFilter();
        f.addAction(Intent.ACTION_PACKAGE_ADDED);
        f.addAction(Intent.ACTION_PACKAGE_REMOVED);
        f.addAction(Intent.ACTION_PACKAGE_REPLACED);
        f.addAction(Intent.ACTION_PACKAGE_CHANGED);
        f.addDataScheme("package");
        registerReceiver(pkgWatch, f);
    }

    @Override
    protected void onResume() {
        super.onResume();
        ui.removeCallbacks(tick);
        ui.post(tick);
        if (needReload) {
            needReload = false;
            loadApps();
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        ui.removeCallbacks(tick);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        try {
            unregisterReceiver(pkgWatch);
        } catch (Exception ignored) {
        }
    }

    @Override
    public void onBackPressed() {
        // A home screen never exits on Back.
    }

    // ------------------------------------------------------------------ UI

    private int dp(float v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    private Drawable rounded(int radiusPx, int fill, Integer rippleColor) {
        GradientDrawable base = new GradientDrawable();
        base.setShape(GradientDrawable.RECTANGLE);
        base.setColor(fill);
        base.setCornerRadius(radiusPx);
        if (rippleColor == null) {
            return base;
        }
        GradientDrawable mask = new GradientDrawable();
        mask.setShape(GradientDrawable.RECTANGLE);
        mask.setColor(0xFFFFFFFF);
        mask.setCornerRadius(radiusPx);
        return new RippleDrawable(ColorStateList.valueOf(rippleColor), base, mask);
    }

    private void buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundResource(R.drawable.bg);

        LinearLayout topRow = new LinearLayout(this);
        topRow.setOrientation(LinearLayout.HORIZONTAL);
        topRow.setGravity(Gravity.BOTTOM);
        topRow.setPadding(dp(30), dp(46), dp(30), 0);

        clockView = new TextView(this);
        clockView.setTextColor(COL_CLOCK);
        clockView.setTextSize(64f);
        clockView.setTypeface(Typeface.create("sans-serif-light", Typeface.NORMAL));
        clockView.setIncludeFontPadding(false);
        topRow.addView(clockView, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        batteryView = new TextView(this);
        batteryView.setTextColor(COL_MUTED);
        batteryView.setTextSize(15f);
        batteryView.setPadding(0, 0, 0, dp(10));
        topRow.addView(batteryView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        dateView = new TextView(this);
        dateView.setTextColor(COL_MUTED);
        dateView.setTextSize(16f);
        dateView.setPadding(dp(30), dp(4), dp(30), 0);

        root.addView(topRow, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(dateView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        ScrollView scroller = new ScrollView(this);
        scroller.setFillViewport(true);
        scroller.setVerticalScrollBarEnabled(false);
        scroller.setOverScrollMode(View.OVER_SCROLL_NEVER);

        gridHolder = new LinearLayout(this);
        gridHolder.setOrientation(LinearLayout.VERTICAL);
        gridHolder.setPadding(0, dp(20), 0, dp(110)); // bottom pad clears the navbar bubble
        scroller.addView(gridHolder, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        LinearLayout.LayoutParams slp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        slp.setMargins(dp(16), 0, dp(16), 0);
        root.addView(scroller, slp);

        setContentView(root);
    }

    private void updateHeader() {
        long now = System.currentTimeMillis();
        boolean h24 = DateFormat.is24HourFormat(this);
        Locale loc = Locale.getDefault();
        clockView.setText(new SimpleDateFormat(h24 ? "HH:mm" : "h:mm", loc).format(now));

        String pattern = loc.getLanguage().startsWith("es") ? "EEEE, d 'de' MMMM" : "EEEE, MMMM d";
        String dateText = new SimpleDateFormat(pattern, loc).format(now);
        if (dateText.length() > 0) {
            dateText = Character.toUpperCase(dateText.charAt(0)) + dateText.substring(1);
        }
        dateView.setText(dateText);

        int level = -1;
        Intent batt = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (batt != null) {
            int l = batt.getIntExtra("level", -1);
            int scale = batt.getIntExtra("scale", 100);
            if (l >= 0 && scale > 0) {
                level = Math.round(100f * l / scale);
            }
        }
        batteryView.setText(level >= 0 ? level + "%" : "");
    }

    // ---------------------------------------------------------------- apps

    private static class AppItem {
        String label;
        String pkg;
        Drawable icon;
        Intent launch;
    }

    private void loadApps() {
        final PackageManager pm = getPackageManager();
        final Intent main = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        new Thread(new Runnable() {
            @Override
            public void run() {
                List<ResolveInfo> found = pm.queryIntentActivities(main, 0);
                final ArrayList<AppItem> items = new ArrayList<AppItem>();
                for (int i = 0; i < found.size(); i++) {
                    ActivityInfo ai = found.get(i).activityInfo;
                    if (ai == null || getPackageName().equals(ai.packageName)) {
                        continue;
                    }
                    AppItem it = new AppItem();
                    it.pkg = ai.packageName;
                    try {
                        it.label = ai.loadLabel(pm).toString();
                    } catch (Exception e) {
                        it.label = ai.packageName;
                    }
                    it.icon = ai.loadIcon(pm);
                    it.launch = new Intent(Intent.ACTION_MAIN)
                            .addCategory(Intent.CATEGORY_LAUNCHER)
                            .setComponent(new ComponentName(ai.packageName, ai.name))
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    items.add(it);
                }
                Collections.sort(items, new Comparator<AppItem>() {
                    @Override
                    public int compare(AppItem a, AppItem b) {
                        return a.label.compareToIgnoreCase(b.label);
                    }
                });
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        renderGrid(items);
                    }
                });
            }
        }, "apps-load").start();
    }

    private void renderGrid(List<AppItem> items) {
        if (isFinishing() || gridHolder == null) {
            return;
        }
        gridHolder.removeAllViews();
        LinearLayout row = null;
        int col = 0;
        for (int i = 0; i < items.size(); i++) {
            if (col == 0) {
                row = new LinearLayout(this);
                row.setOrientation(LinearLayout.HORIZONTAL);
                LinearLayout.LayoutParams rlp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                rlp.topMargin = dp(5);
                gridHolder.addView(row, rlp);
            }
            View cell = makeCell(items.get(i));
            LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
            int m = dp(5);
            clp.setMargins(m, 0, m, 0);
            row.addView(cell, clp);
            col = (col + 1) % COLS;
        }
        if (col != 0 && row != null) {
            for (int p = col; p < COLS; p++) {
                View spacer = new View(this);
                row.addView(spacer, new LinearLayout.LayoutParams(0, dp(1), 1f));
            }
        }
    }

    private View makeCell(final AppItem it) {
        FrameLayout cell = new FrameLayout(this);
        cell.setBackground(rounded(dp(18), COL_TILE, COL_TILE_PRESS));

        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setGravity(Gravity.CENTER_HORIZONTAL);
        col.setPadding(dp(6), dp(14), dp(6), dp(12));

        ImageView icon = new ImageView(this);
        icon.setImageDrawable(it.icon);
        col.addView(icon, new LinearLayout.LayoutParams(dp(46), dp(46)));

        TextView label = new TextView(this);
        label.setText(it.label);
        label.setTextColor(COL_LABEL);
        label.setTextSize(12f);
        label.setGravity(Gravity.CENTER);
        label.setSingleLine(true);
        label.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams tlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        tlp.topMargin = dp(9);
        col.addView(label, tlp);

        cell.addView(col, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.CENTER));

        cell.setClickable(true);
        cell.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    startActivity(it.launch);
                } catch (Exception ignored) {
                }
            }
        });
        cell.setOnLongClickListener(new View.OnLongClickListener() {
            @Override
            public boolean onLongClick(View v) {
                try {
                    Intent info = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                            Uri.parse("package:" + it.pkg));
                    info.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    startActivity(info);
                } catch (Exception ignored) {
                }
                return true;
            }
        });
        return cell;
    }
}
