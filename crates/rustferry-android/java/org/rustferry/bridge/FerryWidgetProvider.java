package org.rustferry.bridge;

import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;

/** Internal renderer for the constrained cross-platform widget snapshot. */
public final class FerryWidgetProvider extends AppWidgetProvider {
    @Override
    public void onUpdate(Context context, AppWidgetManager manager, int[] appWidgetIds) {
        FerryBridge.updateWidgets(context, manager, appWidgetIds);
    }
}
