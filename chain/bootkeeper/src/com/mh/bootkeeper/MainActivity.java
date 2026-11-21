package com.mh.bootkeeper;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        tv.setText("MH BootKeeper installed. Reboot to auto-start Termux.");
        setContentView(tv);
        try {
            Intent i = new Intent();
            i.setComponent(new android.content.ComponentName(
                    "com.termux", "com.termux.app.TermuxActivity"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
        } catch (Exception ignored) {}
    }
}