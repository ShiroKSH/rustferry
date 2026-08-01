package org.rustferry.bridge;

import android.app.NativeActivity;
import android.content.Intent;
import android.content.res.Configuration;
import android.os.Bundle;

/** Internal activity generated into the APK. Application authors never edit this class. */
public final class FerryActivity extends NativeActivity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        FerryBridge.attach(this, getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        FerryBridge.handleIntent(this, intent, false);
    }

    @Override
    protected void onStart() {
        super.onStart();
        FerryBridge.lifecycle("foregrounded");
    }

    @Override
    protected void onResume() {
        super.onResume();
        FerryBridge.lifecycle("resumed");
    }

    @Override
    protected void onPause() {
        FerryBridge.lifecycle("paused");
        super.onPause();
    }

    @Override
    protected void onStop() {
        FerryBridge.lifecycle("backgrounded");
        super.onStop();
    }

    @Override
    public void onLowMemory() {
        FerryBridge.lifecycle("low-memory");
        super.onLowMemory();
    }

    @Override
    public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        FerryBridge.configurationChanged(this);
    }

    @Override
    public void onRequestPermissionsResult(
            int requestCode,
            String[] permissions,
            int[] grantResults) {
        FerryBridge.onRequestPermissionsResult(this, requestCode, permissions, grantResults);
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    }

    /** Single private Rust-to-platform boundary. */
    public String ferryInvoke(String operation, String payload) {
        return FerryBridge.invoke(this, operation, payload);
    }
}
