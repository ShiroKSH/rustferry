package org.rustferry.bridge;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Internal receiver for scheduled notifications and background notification actions. */
public final class FerryNotificationReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        FerryBridge.receiveNotification(context, intent);
    }
}
