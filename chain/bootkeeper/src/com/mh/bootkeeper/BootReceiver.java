package com.mh.bootkeeper;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "MHBootKeeper";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) return;
        Log.i(TAG, "BOOT_COMPLETED received; launching Termux");
        try {
            Intent i = new Intent();
            i.setComponent(new android.content.ComponentName(
                    "com.termux", "com.termux.app.TermuxActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                    | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            context.startActivity(i);
        } catch (Exception e) {
            Log.e(TAG, "failed to start Termux: " + e);
        }
    }
}