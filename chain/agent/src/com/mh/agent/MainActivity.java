package com.mh.agent;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.widget.TextView;

/* Just a face for the agent: starting the service is the only thing this screen
   does, and it also prints where the control channel lives. */
public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextView tv = new TextView(this);
        tv.setTextSize(13);
        tv.setPadding(28, 28, 28, 28);
        tv.setText("MH Agent\n\n"
            + "Runs on every boot, re-establishes root ~2 minutes in, and opens its own\n"
            + "sshd on :8023 (independent of Termux).\n\n"
            + "Control channel (127.0.0.1 only -- tunnel in:\n"
            + "  ssh -p 8022 -N -L 8080:127.0.0.1:8080 <box>):\n"
            + "  http://127.0.0.1:8080/status\n"
            + "  http://127.0.0.1:8080/log\n"
            + "  curl -X POST --data 'id' http://127.0.0.1:8080/cmd\n\n"
            + "The root worker polls this app's files dir, so POST /cmd is answered\n"
            + "with root output (look for __RC=).\n");
        setContentView(tv);
        Intent s = new Intent(this, AgentService.class);
        s.putExtra("why", "activity");
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(s);
        else startService(s);
    }
}
