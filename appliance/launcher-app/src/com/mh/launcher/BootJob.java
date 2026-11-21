package com.mh.launcher;

import android.app.job.JobParameters;
import android.app.job.JobService;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Asks the root door (com.mh.agent, 127.0.0.1:8080) to run the box script
 * /data/local/tmp/mh/mh.sh boot, retrying until it prints BOOT-OK: right after
 * boot the door may not be up yet and Wi-Fi may not have its address.
 * The steps themselves live in that script (tools/box/mh.sh in the workspace).
 */
public class BootJob extends JobService {

    private static final String TAG = "MHBoot";
    private static final String DOOR = "http://127.0.0.1:8080/cmd";
    private static final String SCRIPT = "sh /data/local/tmp/mh/mh.sh boot";
    private static final long RETRY_MS = 15000L;
    private static final long GIVE_UP_MS = 8 * 60 * 1000L; // jobs get 10 min max

    private volatile boolean stopped;

    @Override
    public boolean onStartJob(final JobParameters params) {
        stopped = false;
        new Thread(new Runnable() {
            @Override
            public void run() {
                long start = System.nanoTime();
                int attempt = 0;
                while (!stopped && (System.nanoTime() - start) / 1000000L < GIVE_UP_MS) {
                    attempt++;
                    String out = runOnDoor();
                    if (out != null && out.contains("BOOT-OK")) {
                        Log.i(TAG, "boot steps done on attempt " + attempt);
                        break;
                    }
                    Log.i(TAG, "attempt " + attempt + " not done: "
                            + (out == null ? "door unreachable" : out.trim()));
                    try {
                        Thread.sleep(RETRY_MS);
                    } catch (InterruptedException e) {
                        break;
                    }
                }
                jobFinished(params, false);
            }
        }, "mh-boot").start();
        return true;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        stopped = true;
        return false;
    }

    private String runOnDoor() {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(DOOR).openConnection();
            c.setConnectTimeout(5000);
            c.setReadTimeout(40000);
            c.setRequestMethod("POST");
            c.setDoOutput(true);
            OutputStream os = c.getOutputStream();
            os.write(SCRIPT.getBytes("UTF-8"));
            os.close();
            InputStream is = c.getInputStream();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] b = new byte[2048];
            int n;
            while ((n = is.read(b)) > 0) {
                buf.write(b, 0, n);
            }
            is.close();
            return buf.toString("UTF-8");
        } catch (Exception e) {
            return null;
        } finally {
            if (c != null) {
                c.disconnect();
            }
        }
    }
}
