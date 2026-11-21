package com.mh.launcher;

import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;

/**
 * After a reboot, hands off to {@link BootJob}, which brings back what doesn't
 * survive one: the clock (dead RTC), the paused Askey loggers and AdGuard Home.
 * The only background work the launcher does, once per boot.
 */
public class BootReceiver extends BroadcastReceiver {

    static final int JOB_ID = 1;

    @Override
    public void onReceive(Context c, Intent i) {
        if (!Intent.ACTION_BOOT_COMPLETED.equals(i.getAction())) {
            return;
        }
        JobScheduler js = (JobScheduler) c.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        if (js == null) {
            return;
        }
        js.schedule(new JobInfo.Builder(JOB_ID, new ComponentName(c, BootJob.class))
                .setOverrideDeadline(0)
                .build());
    }
}
