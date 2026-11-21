package com.mh.agent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

/* The whole point of this app: after a reboot, the box re-roots itself with nobody
   touching it.  A BOOT_COMPLETED receiver is enough for that on this Android (8.1):
   the broadcast needs no user interaction, and a foreground service started from it
   keeps running. */
public class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context c, Intent i) {
        Intent s = new Intent(c, AgentService.class);
        s.putExtra("why", "boot " + (i == null ? "?" : i.getAction()));
        if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(s);
        else c.startService(s);
    }
}
